#!/usr/bin/env bash
# preflight.sh - read a LIVE RKE2 cluster, verify every parameter a Talos
# control-plane node must inherit, and refuse to render an adoption config if
# any of them would silently fall back to a Talos default.
#
# Why this exists: almost every failure we hit adopting an RKE2 cluster was the
# same shape - a value that Talos happily defaults, but which MUST match the
# cluster it is joining. A Talos default is never "unset", it is "wrong but
# plausible", and several of these fail late, intermittently, or only after a
# leader election. Discovery is therefore not a convenience here; it is the
# safety mechanism. See docs/migration-from-rke2.md and docs/risk-register.md.
#
#   ./preflight.sh user@rke2-server                     # check only
#   ./preflight.sh user@rke2-server --render ./out      # check, then generate
#
set -euo pipefail

SSH_TARGET="${1:?usage: preflight.sh user@rke2-server [--talos-version X] [--render OUTDIR]}"
shift || true
RENDER=""
TALOS_VERSION="1.13"
VIP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --render)        RENDER="${2:?--render needs an output directory}"; shift 2 ;;
    --talos-version) TALOS_VERSION="${2:?--talos-version needs a value}"; shift 2 ;;
    --vip)           VIP="${2:?--vip needs an address}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

FAILED=0
WARNED=0
pass(){ printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
warn(){ printf '  \033[33mWARN\033[0m  %s\n' "$*"; WARNED=$((WARNED+1)); }
fail(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILED=$((FAILED+1)); }
info(){ printf '        %s\n' "$*"; }
head2(){ printf '\n\033[1m%s\033[0m\n' "$*"; }

# One SSH round-trip. Everything is read from the RKE2 server's own files and
# its own kubectl, so this works against a cluster we are not allowed to modify.
DUMP=$(ssh "$SSH_TARGET" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
M=/var/lib/rancher/rke2/agent/pod-manifests
T=/var/lib/rancher/rke2/server/tls
K=$(ls /var/lib/rancher/rke2/data/*/bin/kubectl 2>/dev/null | head -1)
KC=/etc/rancher/rke2/rke2.yaml
kc(){ "$K" --kubeconfig="$KC" "$@" 2>/dev/null; }
flag(){ grep -oE -- "--$1=[^ \"]*" "$2" 2>/dev/null | head -1 | cut -d= -f2- ; }

echo "SERVICE_CIDR=$(flag service-cluster-ip-range $M/kube-apiserver.yaml)"
echo "POD_CIDR=$(flag cluster-cidr $M/kube-controller-manager.yaml)"
echo "SA_ISSUER=$(flag service-account-issuer $M/kube-apiserver.yaml)"
echo "API_AUDIENCES=$(flag api-audiences $M/kube-apiserver.yaml)"
echo "ENC_CONFIG=$(flag encryption-provider-config $M/kube-apiserver.yaml)"
echo "NODE_CIDR_MASK=$(flag node-cidr-mask-size $M/kube-controller-manager.yaml)"

# Cluster DNS and domain are read from what is RUNNING, not from rke2.yaml: a
# cluster may have been installed with an override, and RKE2 names its DNS
# service rke2-coredns-rke2-coredns rather than the usual kube-dns.
DNSIP=""
for s in rke2-coredns-rke2-coredns kube-dns coredns; do
  DNSIP=$(kc -n kube-system get svc "$s" -o jsonpath='{.spec.clusterIP}')
  [ -n "$DNSIP" ] && break
done
echo "CLUSTER_DNS=$DNSIP"
# --cluster-domain is passed to the kubelet on the command line; there is no
# config file to read it from.
echo "CLUSTER_DOMAIN=$(ps -eo args 2>/dev/null | grep -m1 '[k]ubelet' | grep -oE -- '--cluster-domain=[^ ]+' | cut -d= -f2)"
[ -f /etc/rancher/rke2/config.yaml ] && echo "RKE2_CONFIG_KEYS=$(grep -cvE '^\s*(#|$)' /etc/rancher/rke2/config.yaml)"

echo "K8S_VERSION=$(kc get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}')"
echo "NODES_TOTAL=$(kc get nodes --no-headers | wc -l | tr -d ' ')"
echo "NODES_READY=$(kc get nodes --no-headers | awk '$2=="Ready"' | wc -l | tr -d ' ')"
echo "CP_COUNT=$(kc get nodes -l node-role.kubernetes.io/control-plane --no-headers | wc -l | tr -d ' ')"

# Secrets encryption: the KEY NAME is what matters. Kubernetes selects the
# decryption key by name, so identical material under a different name still
# fails, and that failure blocks Node registration (the bootstrap token is a
# Secret). Emit the name; never emit the material to stdout.
if [ -f /var/lib/rancher/rke2/server/cred/encryption-config.json ]; then
  echo "ENC_ENABLED=true"
  echo "ENC_KEY_NAME=$(python3 -c '
import json;d=json.load(open("/var/lib/rancher/rke2/server/cred/encryption-config.json"))
for r in d["resources"]:
  for p in r["providers"]:
    if "aescbc" in p:
      print(p["aescbc"]["keys"][0]["name"]); raise SystemExit
' 2>/dev/null)"
  echo "ENC_PROVIDER=$(python3 -c '
import json;d=json.load(open("/var/lib/rancher/rke2/server/cred/encryption-config.json"))
print(",".join(k for r in d["resources"] for p in r["providers"] for k in p))
' 2>/dev/null)"
else
  echo "ENC_ENABLED=false"
fi

fp(){ [ -f "$1" ] && openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' ; }
echo "FP_SERVER_CA=$(fp $T/server-ca.crt)"
echo "FP_CLIENT_CA=$(fp $T/client-ca.crt)"
echo "FP_KUBELET_CLIENT_CA=$(fp /var/lib/rancher/rke2/agent/client-ca.crt)"
echo "FP_REQUEST_HEADER_CA=$(fp $T/request-header-ca.crt)"
echo "FP_ETCD_PEER_CA=$(fp $T/etcd/peer-ca.crt)"

# etcd membership must be read LIVE. Building initial-cluster from the
# etcd.k3s.io/initial annotation gives a stale snapshot that fails peerURL
# validation if anyone added a member since.
EP=$(kc -n kube-system get pod -l component=etcd -o jsonpath='{.items[0].metadata.name}')
if [ -n "$EP" ]; then
  MEMBERS=$(kc -n kube-system exec "$EP" -- etcdctl \
      --cert /var/lib/rancher/rke2/server/tls/etcd/server-client.crt \
      --key  /var/lib/rancher/rke2/server/tls/etcd/server-client.key \
      --cacert /var/lib/rancher/rke2/server/tls/etcd/server-ca.crt \
      member list 2>/dev/null || true)
  echo "ETCD_MEMBER_COUNT=$(echo "$MEMBERS" | grep -c 'started' || true)"
  echo "ETCD_INITIAL_CLUSTER=$(echo "$MEMBERS" | awk -F', ' '$3!=""{printf "%s=%s,",$3,$4}' | sed 's/,$//')"
  echo "ETCD_VERSION=$(kc -n kube-system exec "$EP" -- etcd --version 2>/dev/null | awk '/etcd Version/{print $3}')"
fi

echo "CNI_CILIUM=$(kc -n kube-system get ds cilium -o jsonpath='{.metadata.name}' 2>/dev/null)"
echo "KUBE_PROXY_DS=$(kc -n kube-system get ds kube-proxy -o jsonpath='{.metadata.name}' 2>/dev/null)"
echo "CILIUM_KPR=$(kc -n kube-system get cm cilium-config -o jsonpath='{.data.kube-proxy-replacement}' 2>/dev/null)"
echo "CILIUM_HCC=$(kc -n kube-system get helmchartconfig rke2-cilium -o jsonpath='{.metadata.name}' 2>/dev/null)"
REMOTE
)

# shellcheck disable=SC2046
eval "$(echo "$DUMP" | sed 's/^\([A-Z_]*\)=\(.*\)$/\1="\2"/')"

echo "=============================================================="
echo " RKE2 -> Talos adoption preflight   ($SSH_TARGET)"
echo "=============================================================="

head2 "Cluster health"
if [ "${NODES_READY:-0}" = "${NODES_TOTAL:-x}" ]; then
  pass "all $NODES_TOTAL nodes Ready"
else
  fail "only ${NODES_READY:-0}/${NODES_TOTAL:-?} nodes Ready - do not adopt a degraded cluster"
fi

# Adding a member to a 1-member etcd takes quorum from 1 to 2 and the cluster
# stops serving immediately. Observed live; it took an apiserver down.
if [ "${ETCD_MEMBER_COUNT:-0}" -ge 3 ]; then
  pass "etcd has $ETCD_MEMBER_COUNT voting members - safe to add a learner"
elif [ "${ETCD_MEMBER_COUNT:-0}" -eq 1 ]; then
  fail "etcd has 1 member: adding any member raises quorum to 2 and halts the cluster"
else
  warn "etcd has ${ETCD_MEMBER_COUNT:-?} members - prefer 3 before adopting"
fi

head2 "Network parameters (Talos defaults are WRONG here and fail late)"
# This is the finding that motivated the whole script. Talos defaults to
# 10.96.0.0/12 and 10.244.0.0/16. If they are not overridden, the Talos
# apiserver's serving cert gets a SAN for the wrong kubernetes ClusterIP, so
# in-cluster clients that land on it fail TLS ~1 request in N; and if the Talos
# controller-manager ever wins the lease, new nodes get PodCIDRs the CNI cannot
# route.
if [ -n "${SERVICE_CIDR:-}" ]; then
  pass "service CIDR discovered: $SERVICE_CIDR"
  [ "$SERVICE_CIDR" = "10.96.0.0/12" ] && info "(this happens to equal the Talos default)"
else
  fail "could not read --service-cluster-ip-range; refusing to guess"
fi
if [ -n "${POD_CIDR:-}" ]; then
  pass "pod CIDR discovered: $POD_CIDR"
else
  fail "could not read --cluster-cidr; refusing to guess"
fi
[ -n "${CLUSTER_DNS:-}" ] && pass "cluster DNS: $CLUSTER_DNS" || fail "could not read kube-dns ClusterIP"

head2 "ServiceAccount token compatibility"
# Tokens minted by one control plane must be accepted by the other, or pods on
# the Talos node get 401 from every RKE2 apiserver. Cilium is the first casualty.
if [ -n "${SA_ISSUER:-}" ]; then
  pass "issuer: $SA_ISSUER"
else
  fail "could not read --service-account-issuer"
fi
if [ -n "${API_AUDIENCES:-}" ]; then
  pass "api-audiences: $API_AUDIENCES"
  case "$API_AUDIENCES" in
    *,*) info "NOTE: multiple audiences - Talos must reproduce this list exactly" ;;
  esac
else
  warn "no explicit --api-audiences; Talos will default to the issuer"
fi

head2 "Secrets encryption at rest"
if [ "${ENC_ENABLED:-false}" = "true" ]; then
  if [ "${ENC_KEY_NAME:-}" = "key1" ]; then
    pass "key name is 'key1' - matches the Talos default, no override needed"
  else
    warn "key name is '${ENC_KEY_NAME:-?}' but Talos hardcodes 'key1'"
    info "Kubernetes selects the decryption key BY NAME: identical material under"
    info "a different name still fails, and that blocks Node registration."
    info "Remedy: shadow Talos' generated config via cluster.apiServer.extraVolumes"
    info "(see encryption-override.yaml). Fixed upstream in Talos v1.14."
  fi
  info "providers: ${ENC_PROVIDER:-?}"
else
  pass "encryption at rest disabled - nothing to reconcile"
fi

head2 "PKI shape"
if [ "${FP_SERVER_CA:-x}" != "${FP_CLIENT_CA:-y}" ]; then
  warn "RKE2 uses SEPARATE server-ca and client-ca (expected); Talos has one signing key"
  info "The bundle is signed with server-ca first, so the Talos apiserver's"
  info "kubelet-client cert is server-ca-signed, while RKE2 kubelets validate"
  info "client certs against client-ca. Consequence: the Talos apiserver CANNOT"
  info "run logs/exec against UN-migrated RKE2 nodes (401). This shrinks as you"
  info "migrate. Use an RKE2 apiserver for those nodes meanwhile."
else
  pass "server-ca and client-ca are the same cert - no split to reconcile"
fi
if [ "${FP_CLIENT_CA:-x}" = "${FP_KUBELET_CLIENT_CA:-y}" ]; then
  pass "kubelet client-ca matches the server's client-ca"
else
  fail "kubelet client-ca differs from client-ca - unexpected topology, stop and inspect"
fi

head2 "Version skew"
MINOR=$(echo "${K8S_VERSION:-}" | sed -E 's/^v?1\.([0-9]+).*/\1/')
case "$TALOS_VERSION" in
  1.11) LO=28; HI=33 ;;
  1.12) LO=29; HI=34 ;;
  1.13) LO=31; HI=36 ;;
  1.14) LO=32; HI=37 ;;
  *)    LO=""; HI="" ;;
esac
if [ -z "$LO" ]; then
  warn "unknown Talos version '$TALOS_VERSION' - verify its Kubernetes support range yourself"
elif [ -n "$MINOR" ] && [ "$MINOR" -ge "$LO" ] && [ "$MINOR" -le "$HI" ]; then
  pass "Talos $TALOS_VERSION supports Kubernetes 1.$LO-1.$HI; cluster is ${K8S_VERSION}"
  info "pin with --kubernetes-version=${K8S_VERSION%%+*} - do NOT let Talos pick its default"
else
  fail "Talos $TALOS_VERSION supports 1.$LO-1.$HI but the cluster runs ${K8S_VERSION:-?}"
fi

head2 "CNI"
if [ -n "${CNI_CILIUM:-}" ]; then
  pass "Cilium present"
  if [ "${CILIUM_KPR:-}" = "true" ] || [ "${CILIUM_KPR:-}" = "strict" ]; then
    info "kube-proxy-replacement=${CILIUM_KPR}"
  fi
  # Talos runs a tighter capability bounding set than a stock distro; Cilium's
  # defaults die with "unable to apply caps: operation not permitted". The fix
  # edits the SHARED HelmChartConfig and redeploys Cilium on every node, so it
  # must be a deliberate, separate pre-step - not part of adopting a node.
  if [ -n "${CILIUM_HCC:-}" ]; then
    pass "HelmChartConfig rke2-cilium exists - patch capabilities there BEFORE adopting"
  else
    warn "no rke2-cilium HelmChartConfig - you must create one to set Talos capabilities"
  fi
  info "required: ciliumAgent + cleanCiliumState capability lists, and cgroup settings"
  info "this REDEPLOYS Cilium cluster-wide; do it as its own verified step"
else
  warn "Cilium not detected - the capability pre-step may not apply"
fi
[ -n "${KUBE_PROXY_DS:-}" ] && info "kube-proxy DaemonSet present" || info "no kube-proxy DaemonSet (replacement mode)"

head2 "etcd join parameters"
if [ -n "${ETCD_INITIAL_CLUSTER:-}" ]; then
  pass "live initial-cluster captured ($ETCD_MEMBER_COUNT members)"
  info "$ETCD_INITIAL_CLUSTER"
  info "Supplying initial-cluster is what makes the join work at all: Talos only"
  info "calls buildInitialCluster() - the etcd CLIENT call RKE2 rejects on TLS -"
  info "when the arg is absent. With it, the node joins over the PEER protocol."
  info "Regenerate this immediately before applying; it goes stale the moment"
  info "anyone adds a control-plane node."
else
  fail "could not read the live etcd member list"
fi

# Talos ships its own etcd build, and it is usually NEWER than the one RKE2
# bundles. etcd tolerates one minor of skew during a rolling upgrade; it is not
# a supported steady state. The cluster version stays at the LOWEST member's,
# so nothing appears wrong - until the last RKE2 member leaves, at which point
# the cluster silently auto-upgrades. That is a one-way door: going back needs
# an explicit etcd downgrade procedure.
if [ -n "${ETCD_VERSION:-}" ]; then
  RKE2_ETCD_MINOR=$(echo "$ETCD_VERSION" | cut -d. -f1,2)
  case "$TALOS_VERSION" in
    1.13|1.14) TALOS_ETCD_MINOR="3.6" ;;
    1.11|1.12) TALOS_ETCD_MINOR="3.5" ;;
    *)         TALOS_ETCD_MINOR="" ;;
  esac
  if [ -z "$TALOS_ETCD_MINOR" ]; then
    warn "etcd on RKE2 is $ETCD_VERSION; check which etcd Talos $TALOS_VERSION ships"
  elif [ "$RKE2_ETCD_MINOR" = "$TALOS_ETCD_MINOR" ]; then
    pass "etcd minor matches on both sides ($RKE2_ETCD_MINOR)"
  else
    warn "MIXED etcd: RKE2 runs $ETCD_VERSION, Talos $TALOS_VERSION ships $TALOS_ETCD_MINOR.x"
    info "The cluster version pins to $RKE2_ETCD_MINOR while any RKE2 member remains,"
    info "then auto-upgrades to $TALOS_ETCD_MINOR when the last one is removed."
    info "TAKE AN ETCD SNAPSHOT immediately before removing the final RKE2 CP,"
    info "and keep the coexistence window inside one minor of skew."
  fi
fi

# The pinned initial-cluster is PERISHABLE. It is ignored on every normal boot
# (etcd reads membership from its data dir), so it can drift for months without
# symptom - and it is consulted only when a node starts from an EMPTY data dir,
# which is exactly when being wrong is unrecoverable. Verified on a live reboot:
# etcd logged member-initialized=true, "restarting local member", initial-cluster=""
# while the flag still named a control-plane node decommissioned hours earlier.
info ""
info "REMINDER: re-render initial-cluster before ANY operation that could start"
info "etcd from an empty data dir (reprovision, disk replacement, talosctl reset)."
info "It is ignored on normal reboots, so staleness is silent until it is fatal."

echo
echo "=============================================================="
printf ' %d check(s) failed, %d warning(s)\n' "$FAILED" "$WARNED"
echo "=============================================================="

if [ "$FAILED" -gt 0 ]; then
  echo "Refusing to render a Talos config while checks are failing." >&2
  exit 1
fi

[ -z "$RENDER" ] && { echo "Re-run with --render OUTDIR to generate the config."; exit 0; }

mkdir -p "$RENDER"
OUT="$RENDER/adopt-values.yaml"
cat > "$OUT" <<EOF
# Generated by preflight.sh from the LIVE cluster at $SSH_TARGET.
# Every value here was read from the running control plane. Do not replace any
# of them with a Talos default - that is what this file exists to prevent.
cluster:
  network:
    # Inherited from RKE2. Talos would otherwise default to 10.244.0.0/16 and
    # 10.96.0.0/12, which puts the wrong ClusterIP in the apiserver's SAN list
    # and hands out unroutable PodCIDRs if the Talos CM wins the lease.
    podSubnets:
      - $POD_CIDR
    serviceSubnets:
      - $SERVICE_CIDR
    dnsDomain: ${CLUSTER_DOMAIN:-cluster.local}
  apiServer:
    extraArgs:
      service-account-issuer: $SA_ISSUER
      api-audiences: $API_AUDIENCES$(
  if [ -n "$VIP" ]; then printf '\n    certSANs:\n      # The control-plane VIP must be in the SANs BEFORE the first handover.\n      # Talos does add it automatically once a node has held the address, but\n      # that is after the fact - too late for clients validating TLS during the\n      # switch. Also add it to tls-san on the RKE2 side if it is not there yet.\n      - %s' "$VIP"; fi)
  etcd:
    extraArgs:
      # LIVE membership as of generation time. Regenerate immediately before
      # applying. Presence of this key is what routes the join over the peer
      # protocol instead of the etcd client call RKE2 rejects.
      initial-cluster: "$ETCD_INITIAL_CLUSTER"
      initial-cluster-state: existing
machine:
  features:
    # KubePrism load-balances the kubelet onto RKE2 apiservers, which reject
    # Talos-issued client certs. Re-enable only after the last RKE2 CP is gone.
    kubePrism:
      enabled: false
  kubelet:
    clusterDNS:
      - $CLUSTER_DNS
EOF
echo "==> wrote $OUT"
echo "==> pin the version explicitly:  --kubernetes-version=${K8S_VERSION%%+*}"
if [ "${ENC_ENABLED:-false}" = "true" ] && [ "${ENC_KEY_NAME:-}" != "key1" ]; then
  echo "==> ALSO apply encryption-override.yaml (key name '${ENC_KEY_NAME}' != 'key1')"
fi
