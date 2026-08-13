#!/usr/bin/env bash
#
# Capture the supervisor protocol contract from a REAL rke2 server of a given
# version, into conformance/testdata/<version>/.
#
# This is the ground truth the shim is tested against. Run it for every RKE2
# version you intend to support, and re-run it when you plan an upgrade -
# BEFORE the upgrade reaches production.
#
#   ./capture.sh v1.31.8+rke2r1 user@rke2-server
#
# The target host is a throwaway VM. rke2 is uninstalled and reinstalled at the
# requested version, so do not point this at anything you care about.
set -euo pipefail

VERSION="${1:?usage: capture.sh <rke2-version> <ssh-target>}"
TARGET="${2:?usage: capture.sh <rke2-version> <ssh-target>}"
TOKEN="${TOKEN:-conformance-token}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/testdata/$VERSION"
mkdir -p "$OUT"

echo "==> [$VERSION] installing reference server on $TARGET"
ssh "$TARGET" "bash -s" <<EOS
set -e
sudo systemctl stop rke2-server 2>/dev/null || true
sudo /usr/local/bin/rke2-uninstall.sh >/dev/null 2>&1 || true
curl -sfL https://get.rke2.io -o /tmp/i.sh
sudo INSTALL_RKE2_VERSION='$VERSION' sh /tmp/i.sh >/dev/null
sudo mkdir -p /etc/rancher/rke2
printf 'token: $TOKEN\nwrite-kubeconfig-mode: "0644"\n' | sudo tee /etc/rancher/rke2/config.yaml >/dev/null
sudo systemctl enable --now rke2-server >/dev/null 2>&1 &
EOS

echo "==> waiting for the supervisor"
for i in $(seq 1 60); do
  if ssh "$TARGET" "curl -sk --max-time 3 https://127.0.0.1:9345/cacerts -o /dev/null -w '%{http_code}'" 2>/dev/null | grep -q 200; then
    break
  fi
  sleep 10
done

echo "==> capturing endpoint contract"
ssh "$TARGET" "bash -s" <<EOS > "$OUT/endpoints.txt"
S=https://127.0.0.1:9345
A="-u node:$TOKEN"
for p in /v1-rke2/config /v1-rke2/readyz /v1-rke2/apiservers /v1-rke2/client-ca.crt /v1-rke2/server-ca.crt; do
  printf "GET  %-40s %s\n" "\$p" "\$(curl -sk -o /dev/null -w '%{http_code}' \$A "\$S\$p")"
done
for p in /v1-rke2/serving-kubelet.crt /v1-rke2/client-kubelet.crt /v1-rke2/client-kube-proxy.crt /v1-rke2/client-rke2-controller.crt; do
  printf "POST %-40s %s (no node headers)\n" "\$p" "\$(curl -sk -o /dev/null -X POST -w '%{http_code}' \$A "\$S\$p")"
done
EOS

echo "==> capturing agent config"
# Scrub secret-shaped fields: the capture comes from a throwaway cluster, and
# this file is both committed AND served to real agents.
ssh "$TARGET" "curl -sk -u node:$TOKEN https://127.0.0.1:9345/v1-rke2/config" \
  | python3 -c '
import json,sys
d=json.load(sys.stdin)
for k in ("IPSECPSK",):
    if d.get(k): d[k]=""
json.dump(d,sys.stdout,indent=2,sort_keys=True)
' > "$OUT/config.json"

echo "==> capturing rke2 version string"
ssh "$TARGET" "sudo rke2 --version | head -1" > "$OUT/version.txt"

echo
echo "==> captured into $OUT"
ls -1 "$OUT" | sed 's/^/    /'
echo
echo "Review the diff against the previously supported version before shipping:"
echo "    git diff conformance/testdata/"
