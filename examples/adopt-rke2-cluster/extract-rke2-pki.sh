#!/usr/bin/env bash
# Extract an RKE2 cluster's PKI into the kubeadm-shaped directory that
# `talosctl gen secrets --from-kubernetes-pki` expects, so a Talos control-plane
# node can adopt the cluster's identity. See docs/migration-from-rke2.md.
set -euo pipefail
RKE2_SSH="${1:?usage: extract-rke2-pki.sh user@rke2-server [outdir]}"
OUT="${2:-./pki}"
T=/var/lib/rancher/rke2/server/tls
mkdir -p "$OUT/etcd"
get(){ ssh "$RKE2_SSH" "sudo cat $1"; }

# RKE2 keeps SEPARATE server-ca and client-ca; Talos has one cluster CA. Bundle
# them so Talos trusts client certs issued by either, and sign with server-ca so
# Talos' apiserver serving cert is trusted by existing RKE2 kubelets.
get "$T/server-ca.crt" >  "$OUT/ca.crt"
get "$T/client-ca.crt" >> "$OUT/ca.crt"
get "$T/server-ca.key" >  "$OUT/ca.key"

get "$T/request-header-ca.crt" > "$OUT/front-proxy-ca.crt"
get "$T/request-header-ca.key" > "$OUT/front-proxy-ca.key"
get "$T/service.key"           > "$OUT/sa.key"
openssl ec -in "$OUT/sa.key" -pubout -out "$OUT/sa.pub" 2>/dev/null

# etcd: bundle both, but sign with PEER-ca - RKE2's peer trust requires it, and
# peer traffic is what forms consensus.
get "$T/etcd/peer-ca.crt"   >  "$OUT/etcd/ca.crt"
get "$T/etcd/server-ca.crt" >> "$OUT/etcd/ca.crt"
get "$T/etcd/peer-ca.key"   >  "$OUT/etcd/ca.key"

echo "==> wrote $OUT"
echo "==> aescbc key (NOTE: Talos names it 'key1', RKE2 names it 'aescbckey' -"
echo "    they must match or Secrets are mutually unreadable; see the docs):"
ssh "$RKE2_SSH" 'sudo python3 -c "
import json;d=json.load(open(\"/var/lib/rancher/rke2/server/cred/encryption-config.json\"))
for p in d[\"resources\"][0][\"providers\"]:
    if \"aescbc\" in p:
        for k in p[\"aescbc\"][\"keys\"]: print(\"    name=\"+k[\"name\"], \"secret=\"+k[\"secret\"])
"' || echo "    (no encryption-config.json - encryption at rest may be disabled, which is GOOD for this migration)"
