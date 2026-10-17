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
#
# Environment:
#   TOKEN                 join token for the throwaway server (default: conformance-token)
#   RKE2_INSTALL_SHA256   sha256 of install.sh for a version not pinned below
set -euo pipefail

VERSION="${1:?usage: capture.sh <rke2-version> <ssh-target>}"
TARGET="${2:?usage: capture.sh <rke2-version> <ssh-target>}"
TOKEN="${TOKEN:-conformance-token}"

# VERSION becomes a directory name and part of a URL; TOKEN is written into the
# remote rke2 config. Neither may carry path, shell or YAML syntax.
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$ ]] \
  || { echo "VERSION must look like v1.31.8+rke2r1, got: $VERSION" >&2; exit 2; }
[[ "$TOKEN" =~ ^[A-Za-z0-9._:-]{8,255}$ ]] \
  || { echo "TOKEN must be 8-255 chars of [A-Za-z0-9._:-]" >&2; exit 2; }
case "$TARGET" in -*) echo "refusing ssh target starting with '-'" >&2; exit 2 ;; esac

# install.sh is fetched from the rke2 repository AT THE VERSION TAG (not the
# moving get.rke2.io) and checked against a pinned digest before it runs as
# root. Digests were recorded on 2026-10-17 from the tagged files - trust on
# first use, not a signature. For a new version, review that tag's install.sh,
# then add its digest here or pass RKE2_INSTALL_SHA256.
install_sha256(){
  case "$1" in
    v1.31.8+rke2r1) echo 8d57ffcda9974639891af35a01e9c3c2b8f97ac71075a805d60060064b054492 ;;
    v1.35.7+rke2r1) echo 2d24db2184dd6b1a5e281fa45cc9a8234c889394721746f89b5fe953fdaaf40a ;;
    *) echo "${RKE2_INSTALL_SHA256:-}" ;;
  esac
}
INSTALL_SHA256="$(install_sha256 "$VERSION")"
[[ "$INSTALL_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "no pinned install.sh digest for $VERSION; review the script and set RKE2_INSTALL_SHA256" >&2
  exit 2
}
INSTALL_URL="https://raw.githubusercontent.com/rancher/rke2/${VERSION/+/%2B}/install.sh"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/testdata/$VERSION"
mkdir -p "$OUT"

# Remote scripts are sent as a QUOTED heredoc (nothing expands locally) behind
# a prelude of %q-quoted assignments. The token therefore travels on ssh's
# stdin, never on a command line where `ps` on either host would show it.
remote(){ # remote <script-on-stdin>
  { printf 'set -euo pipefail\n'
    printf 'VERSION=%q TOKEN=%q INSTALL_URL=%q INSTALL_SHA256=%q\n' \
      "$VERSION" "$TOKEN" "$INSTALL_URL" "$INSTALL_SHA256"
    cat
  } | ssh "$TARGET" "bash -s"
}

echo "==> [$VERSION] installing reference server on $TARGET"
remote <<'EOS'
sudo systemctl stop rke2-server 2>/dev/null || true
sudo /usr/local/bin/rke2-uninstall.sh >/dev/null 2>&1 || true
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -sfL "$INSTALL_URL" -o "$tmp"
echo "$INSTALL_SHA256  $tmp" | sha256sum -c --quiet - \
  || { echo "install.sh digest mismatch for $VERSION - refusing to run it" >&2; exit 1; }
sudo INSTALL_RKE2_VERSION="$VERSION" sh "$tmp" >/dev/null
sudo mkdir -p /etc/rancher/rke2
# disable: rke2-kube-proxy reproduces the oracle the committed captures came
# from (Disables/Skips list rke2-kube-proxy, DisableKubeProxy stays false).
# Without it a re-capture drifts from testdata for a reason that is about the
# oracle's setup, not the protocol.
printf 'token: "%s"\nwrite-kubeconfig-mode: "0644"\ndisable:\n  - rke2-kube-proxy\n' "$TOKEN" | sudo tee /etc/rancher/rke2/config.yaml >/dev/null
sudo chmod 600 /etc/rancher/rke2/config.yaml
sudo systemctl enable --now rke2-server >/dev/null 2>&1 &
EOS

echo "==> waiting for the supervisor"
for _ in $(seq 1 60); do
  if ssh "$TARGET" "curl -sk --max-time 3 https://127.0.0.1:9345/cacerts -o /dev/null -w '%{http_code}'" 2>/dev/null | grep -q 200; then
    break
  fi
  sleep 10
done

# curl reads the credentials from a config on stdin (-K -) so they never
# appear in its argv.
echo "==> capturing endpoint contract"
remote <<'EOS' > "$OUT/endpoints.txt"
S=https://127.0.0.1:9345
auth(){ printf 'user = "node:%s"\n' "$TOKEN"; }
for p in /v1-rke2/config /v1-rke2/readyz /v1-rke2/apiservers /v1-rke2/client-ca.crt /v1-rke2/server-ca.crt; do
  printf "GET  %-40s %s\n" "$p" "$(auth | curl -sk -K - -o /dev/null -w '%{http_code}' "$S$p")"
done
for p in /v1-rke2/serving-kubelet.crt /v1-rke2/client-kubelet.crt /v1-rke2/client-kube-proxy.crt /v1-rke2/client-rke2-controller.crt; do
  printf "POST %-40s %s (no node headers)\n" "$p" "$(auth | curl -sk -K - -o /dev/null -X POST -w '%{http_code}' "$S$p")"
done
EOS

echo "==> capturing agent config"
# This file is committed (public) AND served to real agents, so before it is
# written:
#   * secret-shaped fields are blanked (a foreign cluster's IPsec PSK);
#   * the oracle's identity is replaced with documentation values - its
#     hostname, its LAN address, and especially a global IPv6 SAN, which
#     reveals the ISP-delegated prefix and, via an EUI-64 interface ID, the
#     VM's MAC address. RFC 2606 (.example), RFC 5737 (192.0.2.0/24) and
#     RFC 3849 (2001:db8::/32) values are used.
# The mapping is deterministic (by position in SANs), so an unchanged server
# re-captures byte-identically and the nightly drift check stays quiet.
read -r -d '' SCRUB_PY <<'PY' || true
import base64, ipaddress, json, re, sys

d = json.load(sys.stdin)
for k in ("IPSECPSK",):
    if d.get(k):
        d[k] = ""

def service_nets(doc):
    nets = []
    for r in doc.get("ServiceIPRanges") or [doc.get("ServiceIPRange") or {}]:
        try:
            plen = sum(bin(b).count("1") for b in base64.b64decode(r["Mask"]))
            nets.append(ipaddress.ip_network("%s/%d" % (r["IP"], plen), strict=False))
        except Exception:
            pass
    return nets

svc = service_nets(d)
domain = d.get("ClusterDomain") or "cluster.local"
keep = {"localhost", "kubernetes", "kubernetes.default", "kubernetes.default.svc",
        "kubernetes.default.svc." + domain}

repl = {}
if d.get("ServerNodeName"):
    repl[d["ServerNodeName"]] = "oracle.example"
v4 = v6 = names = 0
for san in d.get("SANs") or []:
    if san in repl or san in keep:
        continue
    try:
        ip = ipaddress.ip_address(san)
    except ValueError:
        names += 1
        repl[san] = "san%d.example" % names
        continue
    if ip.is_loopback or any(ip in n for n in svc):
        continue
    if ip.version == 4:
        v4 += 1
        repl[san] = "192.0.2.%d" % (9 + v4)
    else:
        v6 += 1
        repl[san] = "2001:db8::%d" % (9 + v6)   # decimal digits are valid hex

# Identity mappings (re-scrubbing an already-scrubbed capture) are dropped, and
# the rest is applied in ONE pass, longest first, so a replacement can never be
# rewritten again by a later rule.
repl = {o: n for o, n in repl.items() if o != n}
pat = re.compile("|".join(re.escape(o) for o in sorted(repl, key=len, reverse=True))) if repl else None
def scrub(x):
    if isinstance(x, dict):
        return {k: scrub(v) for k, v in x.items()}
    if isinstance(x, list):
        return [scrub(v) for v in x]
    if isinstance(x, str) and pat:
        return pat.sub(lambda m: repl[m.group(0)], x)
    return x

d = scrub(d)
def strings(x):
    if isinstance(x, dict):
        for v in x.values(): yield from strings(v)
    elif isinstance(x, list):
        for v in x: yield from strings(v)
    elif isinstance(x, str):
        yield x
if any(o in s.replace(repl[o], "") for s in strings(d) for o in repl):
    sys.exit("scrub incomplete - refusing to write config.json")
sys.stdout.write(json.dumps(d, indent=2, sort_keys=True))
PY
trap 'rm -f "$OUT/config.json.tmp"' EXIT
# Piped straight into the scrubber: the unscrubbed payload never touches disk
# inside the repository.
remote <<'EOS' | python3 -c "$SCRUB_PY" > "$OUT/config.json.tmp"
printf 'user = "node:%s"\n' "$TOKEN" | curl -sk -K - https://127.0.0.1:9345/v1-rke2/config
EOS
mv "$OUT/config.json.tmp" "$OUT/config.json"

echo "==> capturing rke2 version string"
ssh "$TARGET" "sudo rke2 --version | head -1" > "$OUT/version.txt"

echo
echo "==> captured into $OUT"
for f in "$OUT"/*; do echo "    ${f##*/}"; done
echo
echo "Review the diff against the previously supported version before shipping:"
echo "    git diff conformance/testdata/"
