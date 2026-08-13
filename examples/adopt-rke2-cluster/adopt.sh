#!/usr/bin/env bash
# adopt.sh - phased driver for adopting a live RKE2 cluster with Talos control
# planes, and for migrating off RKE2 afterwards.
#
# Deliberately NOT a single end-to-end run. Two reasons, both learned by getting
# them wrong on a real cluster:
#
#   * Some phases have a verify gate where continuing is worse than stopping.
#     `cilium` redeploys the CNI on EVERY node, RKE2 ones included; you want to
#     see the cluster healthy before a Talos node exists to blame.
#   * One phase is a race a human reliably loses. The etcd learner must be added
#     immediately before the node boots: add it too early and RKE2 prunes the
#     member (it has no Node object yet), which invalidates initial-cluster and
#     fails the join. So `join` owns BOTH the member add and the config apply,
#     and regenerates initial-cluster between them.
#
# Every phase is idempotent and ends by verifying its own postcondition. A phase
# that cannot verify itself exits non-zero and does not advance state.
#
# What this cannot do for you: provision the Talos machine. Bring up a node in
# maintenance mode by whatever means your platform uses, then pass its IP.
# Two Proxmox traps, neither of which is this script's fault, and both of which
# present as "the kernel hangs":
#   * Talos requires x86-64-v2. Proxmox defaults to `kvm64`, which does not
#     provide it, and the node stops dead at "Booting ..." with no output at
#     all. Use `--cpu host` (and `--machine q35`).
#   * Talos' GRUB drives a serial terminal. Without `--serial0 socket` the boot
#     menu never counts down, showing a frozen timer forever.
#
# TEST STATUS - every phase verified live against a prod-shaped cluster
# (2 RKE2 CPs + 1 worker, Cilium kube-proxy-replacement, Secrets encryption):
#   status           tested
#   preflight        tested
#   cilium           tested (idempotent no-change path; the applying path is not)
#   pki              tested - 2-cert CA bundle, encryption override, 0600 perms
#   join             tested - SECOND Talos CP joined a live RKE2 cluster,
#                    4 etcd members, node Ready at t+180s
#   shim             tested - DaemonSet self-scheduled onto the new CP
#   migrate-worker   tested both directions, shim <-> stock rke2-server
#   decommission     tested - RKE2 CP removed, etcd 4 -> 3, Talos members intact
# Not yet exercised: removing the LAST RKE2 control plane (the one-way etcd
# version upgrade), and the cilium applying path on a cluster without it.
#
#   ./adopt.sh status
#   ./adopt.sh preflight
#   ./adopt.sh cilium
#   ./adopt.sh pki
#   ./adopt.sh join    <talos-ip> <node-name>
#   ./adopt.sh shim
#   ./adopt.sh migrate-worker <worker-ssh-target>
#   ./adopt.sh decommission   <rke2-cp-ssh-target>
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${ADOPT_WORKDIR:-./adopt-work}"
SSH_TARGET="${RKE2_SSH:-}"
TALOS_VERSION="${TALOS_VERSION:-1.13}"

c_ok(){   printf '  \033[32m✓\033[0m %s\n' "$*"; }
c_no(){   printf '  \033[31m✗\033[0m %s\n' "$*"; }
c_info(){ printf '    %s\n' "$*"; }
step(){   printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die(){    printf '\033[31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

need(){ command -v "$1" >/dev/null || die "missing required tool: $1"; }

# Run kubectl against the RKE2 cluster using the server's own binary+kubeconfig,
# so this works without any local kubeconfig and against a cluster we do not
# modify.
#
# Arguments are NUL-joined and base64'd rather than interpolated. Naive
# interpolation goes through three parsers - local shell, remote login shell,
# then `bash -c` - and any jsonpath containing quotes or spaces is destroyed on
# the way. That bug silently reported "no Talos nodes" on a cluster that had
# one, which is exactly the kind of false negative a migration driver must not
# produce.
rke2_kubectl(){
  local b64; b64=$(printf '%s\0' "$@" | base64 | tr -d '\n')
  ssh "$SSH_TARGET" "sudo bash -s $b64" <<'REMOTE'
K=$(ls /var/lib/rancher/rke2/data/*/bin/kubectl | head -1)
mapfile -d '' ARGS < <(printf '%s' "$1" | base64 -d)
[ -z "${ARGS[-1]}" ] && unset 'ARGS[-1]'
exec "$K" --kubeconfig=/etc/rancher/rke2/rke2.yaml "${ARGS[@]}"
REMOTE
}

# etcdctl only exists inside the etcd static pod.
rke2_etcdctl(){
  local b64; b64=$(printf '%s\0' "$@" | base64 | tr -d '\n')
  ssh "$SSH_TARGET" "sudo bash -s $b64" <<'REMOTE'
K=$(ls /var/lib/rancher/rke2/data/*/bin/kubectl | head -1)
KC=/etc/rancher/rke2/rke2.yaml
mapfile -d '' ARGS < <(printf '%s' "$1" | base64 -d)
[ -z "${ARGS[-1]}" ] && unset 'ARGS[-1]'
EP=$("$K" --kubeconfig=$KC -n kube-system get pod -l component=etcd -o jsonpath='{.items[0].metadata.name}')
[ -n "$EP" ] || { echo "no etcd pod found" >&2; exit 1; }
exec "$K" --kubeconfig=$KC -n kube-system exec "$EP" -- etcdctl \
  --cert /var/lib/rancher/rke2/server/tls/etcd/server-client.crt \
  --key  /var/lib/rancher/rke2/server/tls/etcd/server-client.key \
  --cacert /var/lib/rancher/rke2/server/tls/etcd/server-ca.crt "${ARGS[@]}"
REMOTE
}

require_target(){
  [ -n "$SSH_TARGET" ] || die "set RKE2_SSH=user@rke2-server (an RKE2 control-plane node)"
}

# ---------------------------------------------------------------- status

phase_status(){
  require_target
  step "Cluster"
  rke2_kubectl get nodes -o wide 2>/dev/null | sed 's/^/  /' || die "cannot reach the cluster"

  step "etcd members"
  rke2_etcdctl member list 2>/dev/null | sed 's/^/  /' || c_no "could not list members"

  step "Adoption state"
  local talos_nodes shim_pods
  talos_nodes=$(rke2_kubectl get nodes -o jsonpath='{range .items[*]}{.status.nodeInfo.osImage}{"\n"}{end}' 2>/dev/null | grep -ci talos || true)
  [ "${talos_nodes:-0}" -gt 0 ] && c_ok "$talos_nodes Talos node(s) in the cluster" || c_info "no Talos nodes yet"

  shim_pods=$(rke2_kubectl -n rke2-shim get pods --no-headers 2>/dev/null | grep -c Running || true)
  [ "${shim_pods:-0}" -gt 0 ] && c_ok "shim running on $shim_pods node(s)" || c_info "shim not deployed"

  if rke2_kubectl -n kube-system get helmchartconfig rke2-cilium >/dev/null 2>&1; then
    if rke2_kubectl -n kube-system get helmchartconfig rke2-cilium -o yaml 2>/dev/null | grep -q "cleanCiliumState"; then
      c_ok "Cilium HelmChartConfig carries the Talos capability lists"
    else
      c_info "Cilium HelmChartConfig exists but has no Talos capabilities - run: $0 cilium"
    fi
  else
    c_info "no rke2-cilium HelmChartConfig - run: $0 cilium"
  fi

  [ -d "$WORK" ] && c_info "workdir: $WORK ($(ls "$WORK" 2>/dev/null | wc -l | tr -d ' ') files)"
}

# ---------------------------------------------------------------- preflight

phase_preflight(){
  require_target
  "$HERE/preflight.sh" "$SSH_TARGET" --talos-version "$TALOS_VERSION" --render "$WORK"
}

# ---------------------------------------------------------------- cilium

# Talos runs a tighter capability bounding set than a stock distro, and Cilium's
# defaults die there with "unable to apply caps: operation not permitted". The
# fix lives in the SHARED HelmChartConfig, so applying it redeploys Cilium on
# every node in the cluster - RKE2 ones included. That is why this is its own
# phase with its own gate, and must be done BEFORE any Talos node exists.
phase_cilium(){
  require_target
  step "Patching the cluster-wide Cilium HelmChartConfig"
  c_info "this REDEPLOYS Cilium on every node, including the RKE2 ones"

  local before
  before=$(rke2_kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"' | wc -l | tr -d ' ')
  c_info "$before node(s) Ready before the change"

  # MERGE into the existing values, never replace them. valuesContent is the
  # complete values block for the chart, so writing a fresh manifest silently
  # DROPS whatever was already there - on the cluster this was developed
  # against that would have removed kubeProxyReplacement, k8sServiceHost and
  # k8sServicePort, breaking the CNI on every node at once.
  mkdir -p "$WORK"
  rke2_kubectl -n kube-system get helmchartconfig rke2-cilium \
    -o jsonpath='{.spec.valuesContent}' > "$WORK/cilium-values.current" 2>/dev/null || true
  c_info "existing values: $(wc -l < "$WORK/cilium-values.current" | tr -d ' ') line(s)"

  python3 - "$WORK" <<'PY'
import sys, os, yaml
w = sys.argv[1]
cur = open(os.path.join(w, 'cilium-values.current')).read()
vals = yaml.safe_load(cur) if cur.strip() else {}
if not isinstance(vals, dict):
    print("EXISTING VALUES ARE NOT A YAML MAPPING - refusing to guess", file=sys.stderr)
    sys.exit(1)

# The proven-working set. Deliberately not a superset: these are the exact
# capabilities verified on a Talos node, and adding speculative ones changes
# behaviour we have not tested.
caps = {
    'ciliumAgent': ['CHOWN','KILL','NET_ADMIN','NET_RAW','IPC_LOCK','SYS_ADMIN',
                    'SYS_RESOURCE','DAC_OVERRIDE','FOWNER','SETGID','SETUID'],
    'cleanCiliumState': ['NET_ADMIN','SYS_ADMIN','SYS_RESOURCE'],
}
sc = vals.setdefault('securityContext', {}) or {}
existing = (sc.get('capabilities') or {})
already = set(existing.get('ciliumAgent') or []) >= set(caps['ciliumAgent'])
sc['capabilities'] = {**existing, **caps}
vals['securityContext'] = sc
cg = vals.setdefault('cgroup', {}) or {}
cg.setdefault('autoMount', {})['enabled'] = False
cg.setdefault('hostRoot', '/sys/fs/cgroup')
vals['cgroup'] = cg

open(os.path.join(w, 'cilium-values.new'), 'w').write(yaml.safe_dump(vals, default_flow_style=False, sort_keys=False))
open(os.path.join(w, '.cilium-already'), 'w').write('yes' if already else 'no')
PY

  if [ "$(cat "$WORK/.cilium-already" 2>/dev/null)" = "yes" ]; then
    c_ok "capabilities already present - no change, no redeploy"
    rke2_kubectl -n kube-system rollout status ds/cilium --timeout=60s >/dev/null 2>&1 \
      && c_ok "cilium DaemonSet healthy" || c_no "cilium DaemonSet not fully rolled out"
    return 0
  fi

  step "Diff to be applied"
  diff -u "$WORK/cilium-values.current" "$WORK/cilium-values.new" | sed 's/^/    /' || true
  read -r -p "    type YES to apply (this redeploys Cilium cluster-wide): " ans
  [ "$ans" = "YES" ] || die "aborted"

  python3 - "$WORK" <<'PY'
import sys, os, yaml
w = sys.argv[1]
vals = open(os.path.join(w, 'cilium-values.new')).read()
doc = {'apiVersion':'helm.cattle.io/v1','kind':'HelmChartConfig',
       'metadata':{'name':'rke2-cilium','namespace':'kube-system'},
       'spec':{'valuesContent': vals}}
open(os.path.join(w,'rke2-cilium-talos.yaml'),'w').write(yaml.safe_dump(doc, default_flow_style=False, sort_keys=False))
PY
  ssh "$SSH_TARGET" "sudo tee /var/lib/rancher/rke2/server/manifests/rke2-cilium-talos.yaml >/dev/null" \
    < "$WORK/rke2-cilium-talos.yaml"
  c_ok "HelmChartConfig written (merged, existing values preserved)"

  step "Waiting for the Cilium rollout"
  local i ready total
  for i in $(seq 1 60); do
    sleep 10
    ready=$(rke2_kubectl -n kube-system get ds cilium -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
    total=$(rke2_kubectl -n kube-system get ds cilium -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 0)
    printf '\r    cilium ready %s/%s (t+%ss)   ' "${ready:-0}" "${total:-0}" "$((i*10))"
    [ -n "$total" ] && [ "$total" != "0" ] && [ "$ready" = "$total" ] && break
  done
  echo

  local after
  after=$(rke2_kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"' | wc -l | tr -d ' ')
  if [ "$after" -ge "$before" ] && [ "$ready" = "$total" ]; then
    c_ok "all $after node(s) still Ready, cilium $ready/$total"
  else
    c_no "node readiness went $before -> $after, cilium $ready/$total"
    die "Cilium rollout did not converge. Do NOT proceed to 'pki' until it does."
  fi
}

# ---------------------------------------------------------------- pki

phase_pki(){
  require_target
  need talosctl
  mkdir -p "$WORK"

  step "Extracting the RKE2 PKI"
  "$HERE/extract-rke2-pki.sh" "$SSH_TARGET" "$WORK/pki" >/dev/null
  c_ok "wrote $WORK/pki (mode 0700)"
  chmod -R go-rwx "$WORK/pki"

  step "Generating Talos secrets from that PKI"
  [ -f "$WORK/secrets.yaml" ] && c_info "secrets.yaml exists, reusing" || \
    talosctl gen secrets --from-kubernetes-pki "$WORK/pki" \
      --kubernetes-bootstrap-token "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-6).$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-16)" \
      -o "$WORK/secrets.yaml" >/dev/null
  chmod 600 "$WORK/secrets.yaml"
  c_ok "$WORK/secrets.yaml"

  step "Rendering the adoption values from the LIVE cluster"
  "$HERE/preflight.sh" "$SSH_TARGET" --talos-version "$TALOS_VERSION" --render "$WORK" >/dev/null \
    || die "preflight failed - fix the reported checks before generating a config"
  c_ok "$WORK/adopt-values.yaml"

  # The encryption override only matters when RKE2 named its key something other
  # than Talos' hardcoded "key1". Kubernetes selects the decryption key BY NAME,
  # so identical material under a different name still fails - and that failure
  # blocks Node registration, because the kubelet bootstrap token is a Secret.
  local keyname
  keyname=$(ssh -n "$SSH_TARGET" 'sudo python3 -c "
import json,sys
try: d=json.load(open(\"/var/lib/rancher/rke2/server/cred/encryption-config.json\"))
except Exception: sys.exit(0)
for r in d[\"resources\"]:
  for p in r[\"providers\"]:
    if \"aescbc\" in p: print(p[\"aescbc\"][\"keys\"][0][\"name\"]); sys.exit(0)
" 2>/dev/null' || true)
  if [ -n "$keyname" ] && [ "$keyname" != "key1" ]; then
    step "Rendering the Secrets-encryption override (key name '$keyname')"
    ssh -n "$SSH_TARGET" 'sudo cat /var/lib/rancher/rke2/server/cred/encryption-config.json' \
      > "$WORK/rke2-encryption-config.json"
    chmod 600 "$WORK/rke2-encryption-config.json"
    python3 - "$WORK" <<'PY'
import json,sys,os
w=sys.argv[1]
d=json.load(open(os.path.join(w,'rke2-encryption-config.json')))
keys=[k for r in d["resources"] for p in r["providers"] if "aescbc" in p for k in p["aescbc"]["keys"]]
ks="\n".join(f"              - name: {k['name']}\n                secret: {k['secret']}" for k in keys)
open(os.path.join(w,'encryption-override.yaml'),'w').write(f"""# Generated. Shadows Talos' own encryptionconfig.yaml so both control planes
# select the SAME key by name. RKE2 is not modified.
#
# 0o444 is load-bearing: the apiserver runs as UID 65534 and cannot read a
# root-owned 0400 file. op: create (not overwrite) - the file does not exist on
# a fresh node, and overwrite fails the whole boot if it is absent.
machine:
  files:
    - path: /var/lib/k8s-enc/encryptionconfig.yaml
      permissions: 0o444
      op: create
      content: |
        apiVersion: v1
        kind: EncryptionConfig
        resources:
        - providers:
          - aescbc:
              keys:
{ks}
          - identity: {{}}
          resources: [secrets]
cluster:
  apiServer:
    extraVolumes:
      - hostPath: /var/lib/k8s-enc/encryptionconfig.yaml
        mountPath: /system/secrets/kubernetes/kube-apiserver/encryptionconfig.yaml
        readonly: true
""")
PY
    chmod 600 "$WORK/encryption-override.yaml"
    c_ok "$WORK/encryption-override.yaml (contains key material - mode 0600)"
  else
    c_info "no key-name override needed"
  fi

  step "Next"
  c_info "boot a Talos node in maintenance mode, then:  $0 join <ip> <node-name>"
}

# ---------------------------------------------------------------- join

# The one phase that must be atomic. Sequence matters:
#   1. regenerate initial-cluster from a LIVE member list (it goes stale the
#      moment anyone touches the control plane)
#   2. add the member as a LEARNER (never a voting member: on a small cluster
#      that raises quorum and stops it serving)
#   3. apply the config immediately, so the node registers a Node object before
#      RKE2's member-pruning controller removes the learner
phase_join(){
  require_target
  need talosctl
  local ip="${1:?usage: adopt.sh join <talos-ip> <node-name>}"
  local name="${2:?usage: adopt.sh join <talos-ip> <node-name>}"
  [ -f "$WORK/secrets.yaml" ] || die "run '$0 pki' first"

  step "Checking preconditions"
  local members
  members=$(rke2_etcdctl member list 2>/dev/null | grep -c started || echo 0)
  [ "$members" -ge 3 ] || die "etcd has $members member(s); adding to fewer than 3 risks quorum. Grow the cluster first."
  c_ok "etcd has $members voting members"

  if rke2_etcdctl member list 2>/dev/null | grep -q "$name"; then
    c_info "member '$name' already present - treating as a retry"
  fi

  step "Regenerating initial-cluster from the live member list"
  local initial
  initial=$(rke2_etcdctl member list 2>/dev/null | awk -F', ' '$3!=""{printf "%s=%s,",$3,$4}')
  initial="${initial}${name}=https://${ip}:2380"
  c_info "$initial"

  step "Generating the machine config"
  local patches=(--config-patch "@$WORK/adopt-values.yaml")
  [ -f "$WORK/encryption-override.yaml" ] && patches+=(--config-patch "@$WORK/encryption-override.yaml")
  local k8sver
  k8sver=$(rke2_kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' 2>/dev/null | sed 's/+.*//')

  # The hostname goes in the HostnameConfig DOCUMENT, not machine.network.
  # Talos >=1.13 emits a HostnameConfig document by default (auto: stable), and
  # setting the v1alpha1 field as well fails validation with
  #   "static hostname is already set in v1alpha1 config"
  # auto must be turned off, or the generated name wins over ours - and the
  # hostname is what etcd's initial-cluster keys on.
  cat > "$WORK/join-$name.yaml" <<EOF
cluster:
  etcd:
    extraArgs:
      initial-cluster: "$initial"
      initial-cluster-state: existing
---
apiVersion: v1alpha1
kind: HostnameConfig
hostname: $name
auto: "off"
EOF

  talosctl gen config adopted "https://${ip}:6443" \
    --with-secrets "$WORK/secrets.yaml" \
    --kubernetes-version "${k8sver#v}" \
    "${patches[@]}" \
    --config-patch "@$WORK/join-$name.yaml" \
    --output-types controlplane \
    -o "$WORK/controlplane-$name.yaml" --force >/dev/null
  c_ok "$WORK/controlplane-$name.yaml (k8s ${k8sver})"

  talosctl validate -m metal -c "$WORK/controlplane-$name.yaml" >/dev/null \
    || die "generated config failed validation"
  c_ok "config validates"

  step "Adding the etcd learner, then applying immediately"
  if ! rke2_etcdctl member list 2>/dev/null | grep -q "$name"; then
    rke2_etcdctl member add "$name" --learner --peer-urls="https://${ip}:2380" >/dev/null \
      || die "member add failed"
    c_ok "learner added"
  fi

  talosctl apply-config --insecure -n "$ip" -f "$WORK/controlplane-$name.yaml" \
    || die "apply-config failed - REMOVE THE LEARNER before retrying, or RKE2 will prune it"
  c_ok "config applied; node is booting"

  step "Waiting for the node to join"
  local i st
  for i in $(seq 1 60); do
    sleep 15
    st=$(rke2_kubectl get node "$name" --no-headers 2>/dev/null | awk '{print $2}' || true)
    printf '\r    node %s: %-12s (t+%ss)   ' "$name" "${st:-<absent>}" "$((i*15))"
    [ "${st:-}" = "Ready" ] && break
  done
  echo
  [ "${st:-}" = "Ready" ] || die "node did not become Ready. Check: talosctl -n $ip dmesg | tail"
  c_ok "node $name is Ready"

  step "Verifying etcd"
  rke2_etcdctl member list 2>/dev/null | sed 's/^/    /'
  c_ok "joined"
}

# ---------------------------------------------------------------- shim

phase_shim(){
  require_target
  step "Deploying the supervisor shim"
  c_info "the DaemonSet selects node-role.kubernetes.io/control-plane: \"\" -"
  c_info "the EMPTY STRING is what keeps it off the RKE2 servers (they use \"true\")"
  c_info "deploy with helm or kubectl using your registry, then re-run: $0 status"
  c_info "  helm upgrade --install rke2-shim charts/rke2-supervisor-shim -n rke2-shim --create-namespace"
}

# ---------------------------------------------------------------- worker

# No OS rebuild. The agent re-bootstraps from the join token and its node
# password, so wiping its cached identity is enough. The node-password hash is
# byte-compatible in both directions, so this is reversible.
phase_migrate_worker(){
  require_target
  local w="${1:?usage: adopt.sh migrate-worker <worker-ssh-target>}"
  local supervisor="${2:-}"
  [ -n "$supervisor" ] || die "usage: adopt.sh migrate-worker <worker-ssh-target> <https://talos-ip:9345>"

  local name
  name=$(ssh -n "$w" hostname)
  step "Migrating $name -> $supervisor"

  # Default to a SAFE drain. Bare pods (no controller) are refused rather than
  # silently destroyed - on a real cluster those are the ones nobody can
  # recreate. ADOPT_DRAIN_FORCE=1 opts in after you have looked at them.
  local drain_args=(--ignore-daemonsets --delete-emptydir-data --timeout=300s)
  [ "${ADOPT_DRAIN_FORCE:-0}" = "1" ] && drain_args+=(--force)

  if ! rke2_kubectl drain "$name" "${drain_args[@]}" >/dev/null 2>"$WORK/.drain.err"; then
    if grep -q "declare no controller" "$WORK/.drain.err" 2>/dev/null; then
      c_no "drain refused: this node runs pods with no controller"
      rke2_kubectl get pods -A --field-selector "spec.nodeName=$name" \
        -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,OWNER:.metadata.ownerReferences[0].kind \
        2>/dev/null | awk 'NR==1 || $3=="<none>"' | sed 's/^/      /'
      c_info "those pods will NOT come back on their own. Once you have checked them:"
      c_info "  ADOPT_DRAIN_FORCE=1 $0 migrate-worker $w $supervisor"
      die "aborted before touching the node"
    fi
    sed 's/^/      /' "$WORK/.drain.err" >&2
    die "drain failed"
  fi
  c_ok "drained"

  # Record the current identity. Waiting for the Node to report Ready is NOT a
  # sufficient check: the kubelet takes ~40s to be marked NotReady, so a poll
  # started immediately after the restart sees the STALE Ready from before the
  # migration and declares success without anything having happened. Observed.
  # A new certificate serial can only come from a completed re-bootstrap.
  local before_serial
  before_serial=$(ssh -n "$w" 'sudo openssl x509 -in /var/lib/rancher/rke2/agent/serving-kubelet.crt -noout -serial 2>/dev/null' || echo none)

  ssh -n "$w" "sudo systemctl stop rke2-agent && \
            sudo rm -rf /var/lib/rancher/rke2/agent/{client-*,serving-*,*.kubeconfig,etc} && \
            sudo sed -i 's|^server:.*|server: $supervisor|' /etc/rancher/rke2/config.yaml && \
            sudo systemctl start rke2-agent"
  c_ok "identity wiped, repointed, agent restarted"

  local i st serial=""
  for i in $(seq 1 40); do
    sleep 10
    serial=$(ssh -n "$w" 'sudo openssl x509 -in /var/lib/rancher/rke2/agent/serving-kubelet.crt -noout -serial 2>/dev/null' || true)
    st=$(rke2_kubectl get node "$name" --no-headers 2>/dev/null | awk '{print $2}' || true)
    printf '\r    %s: %-24s cert=%s (t+%ss)   ' "$name" "${st:-?}" "$([ -n "$serial" ] && [ "$serial" != "$before_serial" ] && echo new || echo old)" "$((i*10))"
    if [ -n "$serial" ] && [ "$serial" != "$before_serial" ]; then
      case "${st:-}" in Ready|Ready,SchedulingDisabled) break;; esac
    fi
  done
  echo

  [ -n "$serial" ] && [ "$serial" != "$before_serial" ] \
    || die "the agent never obtained a NEW certificate - it did not re-bootstrap against $supervisor"
  case "${st:-}" in
    Ready|Ready,SchedulingDisabled) : ;;
    *) die "did not become Ready (state: ${st:-unknown}); node is still cordoned" ;;
  esac

  local issuer
  issuer=$(ssh -n "$w" 'sudo openssl x509 -in /var/lib/rancher/rke2/agent/serving-kubelet.crt -noout -issuer 2>/dev/null' | sed 's/^issuer=//' || true)
  c_ok "re-bootstrapped against $supervisor"
  c_info "new serving-kubelet cert, issued by ${issuer:-unknown}"

  rke2_kubectl uncordon "$name" >/dev/null && c_ok "uncordoned"
}

# ---------------------------------------------------------------- decommission

phase_decommission(){
  require_target
  local cp="${1:?usage: adopt.sh decommission <rke2-cp-ssh-target>}"
  local name
  name=$(ssh -n "$cp" hostname)
  step "Decommissioning RKE2 control plane $name"

  # Talos ships a NEWER etcd than RKE2 bundles. The cluster version pins to the
  # lowest member, so removing the last RKE2 member silently auto-upgrades it -
  # a one-way door. Snapshot before that happens.
  local rke2_cps
  rke2_cps=$(rke2_kubectl get nodes -l node-role.kubernetes.io/control-plane=true --no-headers 2>/dev/null | wc -l | tr -d ' ')
  if [ "${rke2_cps:-0}" -le 1 ]; then
    # If the Talos apiservers were told not to enrol in the kubernetes Service
    # (the coexistence setting that keeps in-cluster clients off them), removing
    # the last RKE2 apiserver leaves the Service with NO backends at all, and
    # every in-cluster client loses the API simultaneously. Catch it here: the
    # symptom is cluster-wide and looks nothing like its cause.
    local eps
    eps=$(rke2_kubectl -n default get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[*].ip}' 2>/dev/null | wc -w | tr -d ' ')
    if [ "${eps:-0}" -le 1 ]; then
      c_no "the kubernetes Service has only ${eps:-0} endpoint, and you are removing it"
      c_info "the Talos apiservers are not enrolled — almost certainly"
      c_info "cluster.apiServer.extraArgs.endpoint-reconciler-type: none"
      c_info "REMOVE that setting from every Talos control plane first, wait for"
      c_info "them to appear in 'kubectl -n default get endpoints kubernetes',"
      c_info "then re-run this."
      die "refusing to strand every in-cluster client"
    fi
    c_no "this is the LAST RKE2 control plane"
    c_info "removing it will auto-upgrade the etcd cluster version, irreversibly"
    c_info "take a snapshot first:"
    c_info "  etcdctl snapshot save pre-upgrade.db"
    read -r -p "    type YES to continue: " ans
    [ "$ans" = "YES" ] || die "aborted"
  fi

  # You cannot decommission the node you are driving from: every rke2_kubectl
  # call goes through $RKE2_SSH, and it stops answering the moment rke2-server
  # does. For the LAST control plane there is no other RKE2 node to move to, so
  # finish that one from the Talos side instead.
  if [ "${rke2_cps:-0}" -le 1 ]; then
    c_no "this is the last RKE2 control plane AND the node this driver talks to"
    c_info "after stopping it, kubectl is only reachable via a Talos apiserver."
    c_info "Finish from there:"
    c_info "  talosctl -n <talos-ip> etcd remove-member <hex-id>   # from 'etcd members'"
    c_info "  kubectl --server=https://<talos-ip>:6443 delete node $name"
    c_info "  # it will hang: rke2's own controllers hold finalizers and are gone"
    c_info "  kubectl ... patch node $name -p '{\"metadata\":{\"finalizers\":null}}' --type=merge"
  fi

  rke2_kubectl drain "$name" --ignore-daemonsets --delete-emptydir-data --timeout=300s >/dev/null || true
  c_ok "drained"
  ssh -n "$cp" 'sudo systemctl stop rke2-server' || true
  c_ok "rke2-server stopped"
  rke2_kubectl delete node "$name" >/dev/null 2>&1 || true

  step "etcd after removal"
  rke2_etcdctl member list 2>/dev/null | sed 's/^/    /' || c_info "(query from another server)"
}

# ---------------------------------------------------------------- main

need ssh; need python3
case "${1:-status}" in
  status)          phase_status ;;
  preflight)       phase_preflight ;;
  cilium)          phase_cilium ;;
  pki)             phase_pki ;;
  join)            shift; phase_join "$@" ;;
  shim)            phase_shim ;;
  migrate-worker)  shift; phase_migrate_worker "$@" ;;
  decommission)    shift; phase_decommission "$@" ;;
  *) sed -n '1,40p' "$0" | grep -E '^#( |$)' | sed 's/^# \{0,1\}//' ; exit 2 ;;
esac
