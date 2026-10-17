#!/usr/bin/env bash
# Extract an RKE2 cluster's PKI into the kubeadm-shaped directory that
# `talosctl gen secrets --from-kubernetes-pki` expects, so a Talos control-plane
# node can adopt the cluster's identity. See docs/migration-from-rke2.md.
#
# The output contains the cluster's CA PRIVATE KEYS (server-ca, request-header-ca,
# service-account, etcd peer-ca). Whoever reads them can mint cluster-admin
# credentials and forge etcd peers, so they are created 0600 inside a 0700
# directory from the first byte - never written world-readable and chmod'ed
# afterwards, which leaves a window and leaves the key readable if the script
# dies in between.
set -euo pipefail
umask 077

RKE2_SSH="${1:?usage: extract-rke2-pki.sh user@rke2-server [outdir]}"
OUT="${2:-./pki}"
T=/var/lib/rancher/rke2/server/tls

# A target beginning with '-' would be parsed by ssh as an option
# (-oProxyCommand=... runs a local command).
case "$RKE2_SSH" in -*) echo "refusing ssh target starting with '-': $RKE2_SSH" >&2; exit 2 ;; esac

install -d -m 700 "$OUT" "$OUT/etcd"
# install -d does not tighten a directory that already existed on every platform.
chmod 700 "$OUT" "$OUT/etcd"

# On failure, remove whatever partial key material was written. Only files this
# run created are removed: $OUT may be an operator directory with other content.
WRITTEN=()
DONE=0
cleanup(){
  [ "$DONE" = 1 ] && return 0
  if [ "${#WRITTEN[@]}" -gt 0 ]; then
    echo "==> extraction failed; removing partial key material" >&2
    for f in "${WRITTEN[@]}"; do
      if command -v shred >/dev/null 2>&1; then shred -u -- "$f" 2>/dev/null || rm -f -- "$f"; else rm -f -- "$f"; fi
    done
  fi
}
trap cleanup EXIT

get(){ ssh -n "$RKE2_SSH" "sudo cat $(printf '%q' "$1")"; }
put(){ WRITTEN+=("$2"); get "$1" > "$2"; }      # create/truncate
add(){ get "$1" >> "$2"; }                       # append to a bundle

# RKE2 keeps SEPARATE server-ca and client-ca; Talos has one cluster CA. Bundle
# them so Talos trusts client certs issued by either, and sign with server-ca so
# Talos' apiserver serving cert is trusted by existing RKE2 kubelets.
put "$T/server-ca.crt" "$OUT/ca.crt"
add "$T/client-ca.crt" "$OUT/ca.crt"
put "$T/server-ca.key" "$OUT/ca.key"

put "$T/request-header-ca.crt" "$OUT/front-proxy-ca.crt"
put "$T/request-header-ca.key" "$OUT/front-proxy-ca.key"
put "$T/service.key"           "$OUT/sa.key"
WRITTEN+=("$OUT/sa.pub")
openssl ec -in "$OUT/sa.key" -pubout -out "$OUT/sa.pub" 2>/dev/null

# etcd: bundle both, but sign with PEER-ca - RKE2's peer trust requires it, and
# peer traffic is what forms consensus.
put "$T/etcd/peer-ca.crt"   "$OUT/etcd/ca.crt"
add "$T/etcd/server-ca.crt" "$OUT/etcd/ca.crt"
put "$T/etcd/peer-ca.key"   "$OUT/etcd/ca.key"

DONE=1
echo "==> wrote $OUT (directory 0700, files 0600)"

# Only the key NAMES are printed. The secret itself never goes to stdout: this
# output ends up in terminal scrollback, CI logs and pasted bug reports.
echo "==> aescbc key name(s) (NOTE: Talos names it 'key1', RKE2 names it 'aescbckey' -"
echo "    they must match or Secrets are mutually unreadable; see the docs):"
ssh -n "$RKE2_SSH" 'sudo python3 -c "
import json;d=json.load(open(\"/var/lib/rancher/rke2/server/cred/encryption-config.json\"))
for r in d[\"resources\"]:
    for p in r[\"providers\"]:
        if \"aescbc\" in p:
            for k in p[\"aescbc\"][\"keys\"]: print(\"    name=\"+k[\"name\"])
"' || echo "    (no encryption-config.json - encryption at rest may be disabled, which is GOOD for this migration)"
echo "    key material: /var/lib/rancher/rke2/server/cred/encryption-config.json on $RKE2_SSH"
echo "    ('adopt.sh pki' copies it into the 0700 workdir and renders the override)"

cat <<EOF

==> $OUT holds the cluster's CA PRIVATE KEYS.
    Once 'talosctl gen secrets --from-kubernetes-pki $OUT' has produced
    secrets.yaml (which carries the same keys), this directory is a redundant
    copy. Remove it:
      Linux:  find "$OUT" -type f -exec shred -u {} + && rm -rf "$OUT"
      macOS:  rm -rf "$OUT"   (overwriting is meaningless on APFS/SSD; rely on FileVault)
    Keep secrets.yaml itself somewhere encrypted - it is the cluster's identity.
EOF
