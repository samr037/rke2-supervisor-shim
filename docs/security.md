# Security

This component signs certificates with the cluster CA. Treat it as part of the
control plane's trust boundary, not as an ordinary workload.

This document covers the threat model, the audit of **2026-10-17** (every
finding, its fix, and how far that fix has been tested), the risks that remain,
and how to verify the published image. The earlier audit, whose four fixes are
still in place, is summarised at the end.

> **Read this first: nothing from the 2026-10-17 audit has been run against a
> real rke2 agent.** The lab VMs used for every live verification elsewhere in
> these docs no longer exist. Every Go change below is covered by unit tests
> (`go test ./...`, green at the merge commit); the chart, manifest, CI and
> script changes are reviewed but not exercised on a cluster. "Fixed" in this
> document means *fixed in code and pinned by a test where one is named*, not
> *verified live*. Re-verify before relying on it, especially the two
> ValidatingAdmissionPolicies and the Cilium host policy, which can refuse
> legitimate traffic if they are wrong. The one exception is the
> `system:rke2-controller` node policy (finding 17), exercised on a k3s cluster
> by impersonation — still not by a real agent.

## Threat model

**Asset.** The cluster CA private key, mounted in the shim pod. Anything that
can sign with it can mint any Kubernetes identity, including cluster-admin.

**Secondary assets.** The join token; the shim's ServiceAccount (it can read
every Secret in `kube-system`); node identities (`system:node:<name>`), because
the Node authorizer lets a node read the Secrets of pods scheduled on it, and
the shim's own pod — which mounts the CA key — is scheduled on a control-plane
node.

**Who can reach what:**

| Attacker position | Gets, by design | Must not get |
| --- | --- | --- |
| Network access to `:9345`, no token | the CA *certificate* from `/cacerts` | anything else; not even a log line per request |
| The join token | a **new** node identity of their choosing; the shared `system:kube-proxy` and `system:rke2-controller` identities | an **existing** node's identity; a certificate valid for anything but their own node; the ability to exhaust the shim |
| A legitimate node's certificate | a tunnel session for that node | a tunnel for another node; unbounded tunnel resources |
| Network access to `:9346` (if exposed) | node names and certificate expiry | anything else |
| The shim's ServiceAccount token | read on `kube-system` Secrets (see residual risks) | write to anything but `*.node-password.rke2` |
| `exec` into the shim pod, or `get` on its Secrets | **the cluster** | — this is the boundary; protect it with RBAC |

The join token is the input most of this audit was about. It is
**node-admin-grade**: it yields new node identities and the shared
`system:rke2-controller` identity, which can modify any Node (see residual
risks). Handle it like a cluster secret, not like a provisioning convenience,
and rotate it.

## Audit of 2026-10-17

Scope: all Go code, the Helm chart, `deploy/`, both CI definitions, the
adoption and conformance scripts, and committed test data.

Severity is the impact if exploited with the access the finding needs. The
**Tested** column says how the fix is pinned: *unit* names the Go test,
*none* means review only. Rows marked **live** were also exercised against a
real shim and a real rke2 agent on 2026-10-17 (see
[Live verification](#live-verification-of-2026-10-17)).

### Summary

| # | Finding | Severity | Tested |
| --- | --- | --- | --- |
| 1 | Token holder could take over any node with no recorded password, including Talos control planes | Critical | unit · **live** |
| 2 | Node name not validated before it became a certificate CN and DNS SAN | High | unit · **live** |
| 3 | Serving-certificate IP SANs taken verbatim from `Rke2-Node-Ip` | High | unit · **live** |
| 4 | Certificates issued with no password check if no store was wired | Medium | unit |
| 5 | Weak CSR public keys accepted | Medium | unit · **live** |
| 6 | scrypt cost and concurrency dictated by stored data and request rate | Medium | unit · **live** |
| 7 | Join token printed by `-h` and on any flag error | Medium | unit · **live** |
| 8 | Tunnel: CN-only identity check, unbounded sessions and message size | Medium | unit · **live** |
| 9 | Missing HTTP timeouts and limits on both listeners | Medium | unit |
| 10 | Leaf lifetime could exceed the CA's; unusable CA accepted at startup | Low | unit |
| 11 | Unauthenticated requests could flood the log at ERROR | Low | unit · **live** |
| 12 | Unusable control-plane addresses advertised; IPv6 mis-formatted | Low | unit |
| 13 | Expiry Events created hourly without bound; metrics for deleted nodes kept forever | Low | unit |
| 14 | `golang.org/x/{net,crypto,text}` behind known vulnerabilities | Medium | govulncheck |
| 15 | Supply chain: mutable `latest` image, unsigned images, actions pinned by tag | High | none |
| 16 | Shim ServiceAccount could write any `kube-system` Secret | High | none |
| 17 | Shared `system:rke2-controller` identity can modify any Node | High | k3s impersonation, 12/12 — mitigation partial · **live** |
| 18 | Cilium host policy opened every host port to every pod | High | none |
| 19 | Chart and manifest hardening gaps; token passed as an environment variable | Low | none |
| 20 | Operator scripts: remote output `eval`'d, key files created world-readable, unvalidated inputs | Medium | none |
| 21 | Conformance capture: unpinned installer run as root, SSH host keys not checked, oracle identity committed | Medium | **live** (re-capture matches testdata byte for byte) |
| 22 | A CSR refused for its key had already enrolled the node password (name squatting) — *found live* | Low | unit · **live** |
| 23 | TCP liveness probe made net/http log a TLS handshake error every 20 s — *found live* | Low | unit |
| 24 | `capture.sh` did not reproduce the oracle the captures came from (`disable: rke2-kube-proxy`) — *found live* | Low | **live** |

### 1. Takeover of nodes that never enrolled — critical

Node passwords are trust-on-first-use: the first request for a name records its
password, later ones must match. "First" was decided by the absence of a
`<node>.node-password.rke2` Secret. But nodes that never came through a
supervisor — **every Talos control plane**, and any kubelet joined by other
means — have a Node object and no Secret. A token holder could request
`client-kubelet.crt` with `Rke2-Node-Name: <talos-cp>` and any password, be
enrolled, and receive `O=system:nodes, CN=system:node:<talos-cp>`.

That identity, through the Node authorizer, can read Secrets referenced by pods
on that node — and the shim pod, which mounts the CA key, runs there. This
chain follows from the Node authorizer's documented rules; it was not
demonstrated on a live cluster.

**Fix.** Before enrolling, the store looks the name up as a Node. If it exists
with no password on record the request gets **409** and an ERROR log naming the
Secret; if the lookup itself fails, the request fails closed. Nodes adopted from
RKE2 are unaffected: RKE2 already wrote their Secret, the hash format is
byte-compatible, and they verify as before.

**Operational change.** "Delete the node-password Secret to let a node
re-register" is no longer enough while the Node object exists. Delete the Secret
**and** the Node object, or recreate the Secret with the node's real password.
See [runbook.md](runbook.md#-migrate-worker--no-os-rebuild) and
[certificates.md](certificates.md).

Tests: `TestExistingNodeWithoutPasswordIsAConflict`,
`TestCheckAndSetRefusesExistingNodeWithoutPassword`,
`TestCheckAndSetAcceptsAdoptedRKE2Node`,
`TestCheckAndSetFailsClosedOnNodeLookupError`, `TestCheckAndSetEnrollsNewNode`.

### 2. Node name not validated — high

`Rke2-Node-Name` became the serving certificate's CN and DNS SAN and the
`system:node:<name>` identity, unchecked. A token holder could request a
kubelet serving certificate, signed by the cluster CA, valid for `localhost`,
`kubernetes.default.svc` or any other name in-cluster clients trust.

**Fix.** Names must be lowercase DNS-1123 subdomains (Kubernetes requires that
of Node names anyway, so nothing legitimate is lost). `localhost`, `kubernetes`,
`kubernetes.*` and anything containing `.svc` are refused. Both give **400**.
Test: `TestNodeNameIsValidated`.

### 3. Serving-certificate IP SANs unrestricted — high

`Rke2-Node-Ip` was copied into the serving certificate's IP SANs. Any address
named there is one the caller can then impersonate a TLS server for, with the
cluster CA's signature — the `kubernetes` Service IP or an apiserver address,
for example.

**Fix.** The header is validated before the password check (so a refusal never
enrols a password as a side effect). Refused with **400**: more than 8 entries,
anything that is not an IP, loopback, unspecified, link-local, multicast,
addresses inside the service CIDR, and the advertised control-plane addresses.
The `127.0.0.1`/`::1` SANs the shim adds itself are unchanged. An unparseable
`--service-cidr` refuses to start the shim rather than failing per request.
Tests: `TestServingCertSANIPsAreRestricted`,
`TestServingCertSANRejectsDiscoveredAPIServer`.

### 4. Fail-open without a password store — medium

If the shim was ever wired without a node-password store, node-scoped
certificates were issued with no password check at all. Not reachable in the
shipped binary, but one refactor away from finding 1 for every node. Now a 500
and an ERROR log. Test: `TestNilPasswordStoreFailsClosed`.

### 5. Weak CSR keys accepted — medium

The CSR's public key is the one thing in an issued certificate the client
chooses. Only ECDSA P-256/P-384/P-521, Ed25519 and RSA ≥ 2048 bits are now
accepted; anything else is **400**. Tests: `TestSignEnforcesPublicKeyPolicy`,
`TestWeakCSRKeyIsABadRequest`.

### 6. scrypt cost unbounded — medium

The scrypt parameters were read from the stored hash and used as-is, so a hash
with a large N made every verification allocate gigabytes; a one-byte derived
key matched one password in 256; trailing data after the hash was ignored; and
every node-scoped request ran scrypt (32 MiB, tens of milliseconds) with no
concurrency bound.

**Fix.** Stored parameters are bounded (N ≤ 2¹⁶, r ≤ 16, p ≤ 4, derived key
32–1024 bytes, canonical form only; rke2 writes N=2¹⁵, r=8, p=1, 64 bytes).
Concurrent scrypt runs are capped at 2 × GOMAXPROCS and waiting respects the
request's context. Node passwords must be 8–256 bytes (rke2 sends 32 hex
characters). `TestVerifyRealRKE2Hash` still passes, so byte-compatibility with
rke2 is unchanged. Tests: `internal/nodepassword/hardening_test.go`,
`TestNodePasswordLengthIsBounded`.

### 7. Join token in usage output — medium

The `--token` flag's default was the value of `SHIM_TOKEN`, and Go's flag
package prints defaults in its usage text — so `-h`, or any mistyped flag,
wrote the token to the pod log.

**Fix.** The token is no longer a flag default. New `--token-file`
(env `SHIM_TOKEN_FILE`), whitespace-trimmed, takes precedence over `--token` and
`SHIM_TOKEN`. An empty token refuses to start (it would have made Basic auth
accept an empty password). The chart and `deploy/shim.yaml` now mount the token
Secret as a file. Tests: `TestUsageNeverContainsTheToken`,
`TestTokenResolution`.

### 8. Tunnel limits — medium

The tunnel authorizer accepted any client certificate whose CN began with
`system:node:`, without checking `O=system:nodes`. `rancher/remotedialer`
v0.6.1 also offers no way to bound what a peer sends: it never sets a websocket
read limit, and one authenticated agent could make the shim buffer a message of
any size, or open any number of sessions.

**Fix**, in the new `internal/tunnel` package: identity requires
`CN=system:node:<n>` **and** `O=system:nodes`; at most 2 concurrent sessions per
node (the second absorbs a reconnect racing the old session's teardown), the
third gets **429**; websocket frame headers are parsed on the hijacked
connection before gorilla/websocket sees the bytes, and a message over 16 KiB
drops the session. Tests: `TestAuthorizeRequiresNodeIdentity`,
`TestTunnelSessionsPerNodeAreCapped`, `TestTunnelMessageSizeIsCapped`,
`TestFrameLimitParsing`.

Not live-verified: that a real agent's traffic stays under 16 KiB is reasoned
from remotedialer's framing (the shim never dials through the tunnel, so agents
report no connections), not captured.

### 9. HTTP timeouts and limits — medium

The supervisor listener had only a header timeout; the metrics listener was a
bare `http.ListenAndServe` with none. A client trickling bytes held a goroutine
and a socket indefinitely.

**Fix.** Supervisor: 2-minute idle timeout, 64 KiB header limit, and a 30 s read
deadline on CSR bodies. It deliberately has no whole-request read/write timeout,
because the tunnel websocket shares the listener and lives for days. Metrics:
header, read, write and idle timeouts and a 16 KiB header limit.
`--metrics-listen=""` now disables the metrics listener; it previously reached
`http.Server` as `""`, which binds `:80` on every interface. Tests:
`TestServersHaveTimeouts`, `TestCSRBodyReadHasADeadline`,
`TestEmptyMetricsListenDisablesMetrics`.

### 10. CA lifetime and CA sanity — low

Leaf `NotAfter` is now capped at the CA's `NotAfter`, and the recorded expiry is
the leaf's real one. The shim refuses to start with a CA that is not a CA, lacks
`certSign`, is outside its validity window, or does not match its key, and with
an unparseable `--pod-cidr` or `--service-cidr`. Each of these used to surface
only when agents failed verification, far from the cause. Tests:
`TestLeafNeverOutlivesCA`, `TestRecordedExpiryIsTheLeafExpiry`,
`TestLoadCARejectsUnusableCA`.

### 11. Log flooding by unauthenticated callers — low

Every request to an unknown path logged at ERROR, for anyone who could reach
`:9345`. Unknown paths now go through authentication first: without the token
they get a quiet **401**, and authentication failures log at WARN at most once a
minute (DEBUG otherwise, with a suppressed count). An authenticated request to
an unknown route still gets **501 + ERROR**, so protocol drift from a real agent
stays loud. Tests: `TestUnauthenticatedRequestsDoNotLogErrors`,
`TestAuthenticatedUnknownEndpointStillFailsLoudly`.

### 12. Control-plane discovery — low

Discovered addresses are now parsed and joined with `net.JoinHostPort`
(IPv6 was emitted as `fd00::1:6443`). Invalid, loopback and unspecified
addresses are skipped with a warning instead of being advertised to every
agent. Test: `TestListFormatsAndFiltersAddresses`.

### 13. Expiry Events and metrics — low

Each hourly scan created a new Event per expiring certificate (24 a day per node
and kind). Events now have a stable name, `<node>.cert-expiry.<kind>` (a hash
when that is not a valid name), and are patched in place. Metric series for
nodes whose Secret is gone are removed, so a deleted node stops alerting.
Tests: `TestScanReusesOneEventPerNodeAndKind`, `TestEventNameIsAlwaysValid`,
`TestScanDropsSeriesForDeletedNodes`.

### 14. Dependencies — medium

Bumped `golang.org/x/net` to 0.61, `x/crypto` to 0.58 and `x/text` to 0.43.
`govulncheck` is clean afterwards except GO-2026-5932 (`x/crypto/openpgp`), a
package this module does not import.

### 15. Supply chain — high

The image holds the CA key, so whoever controls what it pulls controls the
cluster. CI published a moving `latest` tag, images were unsigned, and actions
were referenced by mutable tag.

**Fix.** No `latest`, ever: `main` publishes the commit SHA, a `vX.Y.Z` git tag
publishes `X.Y.Z` (other tag names are refused). Each image is signed keyless
with cosign by digest and gets a SLSA build-provenance attestation. Actions are
pinned by commit SHA with Dependabot keeping them current; the ko version is
explicit; `.ko.yaml` pins the distroless base by digest (without it ko silently
used a different base). The chart and `deploy/shim.yaml` pin a release tag, the
chart accepts a digest, and its schema rejects `latest`. See
[Verifying the image](#verifying-the-image).

Untested: no tag has been pushed through the new workflow yet, so the signing
and attestation steps have not run.

### 16. Secret writes in `kube-system` — high

RBAC cannot match a name suffix, so the node-password Role grants
create/patch on **every** Secret in `kube-system`. A stolen shim
ServiceAccount token could overwrite bootstrap tokens or other controllers'
credentials.

**Fix.** A ValidatingAdmissionPolicy (chart: `secretsAdmissionPolicy.enabled`,
`auto` on Kubernetes ≥ 1.30; raw:
[`deploy/node-password-secret-policy.yaml`](../deploy/node-password-secret-policy.yaml))
limits the shim's ServiceAccount to creating and patching `*.node-password.rke2`
Secrets, and forbids changing an existing Secret's `data` — re-pointing a stored
hash is exactly the impersonation node passwords exist to prevent. It fails
closed. **Reads are not restricted**; admission never sees them. Enforcement has
not been tested against a live apiserver.

### 17. Shared `system:rke2-controller` identity — high, partially mitigated

`client-rke2-controller.crt` takes no node headers, so — exactly as on a real
rke2 server — any token holder can obtain `CN=system:rke2-controller`. Our
ClusterRole grants it `patch`/`update` on `nodes` and `nodes/status`, because
the agent labels its own Node and got 403 without it
([protocol.md](protocol.md#what-a-talos-backed-shim-must-add-on-the-cluster-side)).
The identity is shared by every agent, so RBAC cannot say "your own node": a
token holder can re-taint, cordon or relabel **any** Node.

Upstream rke2 (`pkg/rke2/clusterrole_bootstrap.go` on `main`, read on
2026-10-17) grants this user a different set: `get` on nodes and no `patch`,
plus list/watch on namespaces, networkpolicies, pods, endpoints and
endpointslices, `create` on `serviceaccounts/token`, and read on Helm chart
objects. Why the agent needed `patch` against the shim but not upstream has not
been re-captured; until it is, the broader grant stays and is mitigated rather
than removed.

**Mitigation, added; not exercised by a real rke2 agent.** A
ValidatingAdmissionPolicy (chart: `rke2ControllerAdmissionPolicy.enabled`;
raw: [`deploy/rke2-controller-node-policy.yaml`](../deploy/rke2-controller-node-policy.yaml))
limits that user's Node updates to labels and annotations: no `spec` changes
(taints, `unschedulable`, podCIDR) and no adding, changing or removing
`node-role.kubernetes.io/*` or `node-restriction.kubernetes.io/*` labels.
What remains open: ordinary labels and annotations on any Node (enough to
attract workloads that select on a custom label), and `nodes/status`, which the
policy does not match because what the agent writes there was never captured.

How it was tested: on a k3s v1.31 cluster, by impersonating
`system:rke2-controller` (`kubectl --as`), 12 of 12 allow/deny cases behaved as
intended. That proves the CEL rules; it does not prove a real agent's own label
writes still pass, which is the failure mode that would break joins.

The RBAC objects were also renamed to `rke2-supervisor-shim-rke2-controller`
(chart) and `rke2-shim-rke2-controller` (`deploy/shim.yaml`), so they can never
be the same object as the `system:rke2-controller` ones a real RKE2 server
reconciles during an adoption. If you applied an older `deploy/shim.yaml`,
delete the previous ClusterRole and ClusterRoleBinding named `rke2-controller`.

### 18. Cilium host policy — high (if you used it)

`deploy/cilium-host-policy.yaml` allowed the `remote-node` and `cluster`
entities on **every** port, which opened `:9345`, `:9346`, etcd and the kubelet
to every pod in the cluster. It was written that way because, by default,
Cilium's `fromCIDR` never matches in-cluster nodes, and the per-CIDR rules
silently matched nothing.

**Fix.** Rewritten with explicit per-port rules. It now **requires**
`policyCIDRMatchMode=nodes` in addition to `hostFirewall.enabled=true`; without
it the node-address rules match nothing and the host locks itself out of the
cluster. Stage it in policy audit mode first. Untested on a live cluster. See
[network-security.md](network-security.md#layer-2-cilium-host-firewall-optional).
The NetworkPolicy's apiserver egress was narrowed from any host on 6443 to the
control-plane addresses.

### 19. Pod and chart hardening — low

`seccompProfile: RuntimeDefault` and an explicit `runAsGroup` in both the chart
and `deploy/shim.yaml`; a `values.schema.json` that rejects malformed ports,
CIDRs, IPs, names, path-traversing file names and the `latest` tag; the token
mounted as a file with only its key projected; probes moved to `:9345`
(HTTPS `/cacerts` readiness, TCP liveness) so they no longer depend on the
metrics listener; with `metrics.enabled=false` the chart binds metrics to
`127.0.0.1`.

### 20. Operator scripts — medium

These run on an operator workstation holding the cluster's CA keys.
`preflight.sh` `eval`'d output from the remote RKE2 node, so a compromised node
could run commands on the workstation; it now parses an allowlist of keys and
validates every value before rendering. `adopt.sh` and `extract-rke2-pki.sh`
create key material under `umask 077` from the first byte instead of
`chmod`-ing afterwards, no longer print the Secrets-encryption key, refuse SSH
targets starting with `-` (an `-oProxyCommand=` injection), and validate node
names, IPs and URLs before they reach YAML or a remote shell.
`api-audiences` and other rendered values are now emitted as quoted YAML
scalars. Not covered by automated tests, and not run against a cluster since.

### 21. Conformance capture — medium

The captured config is committed and served to real agents, so the capture path
is part of the supply chain. `capture.sh` piped an unpinned `install.sh` to a
root shell; it now fetches the script from the version's git tag and checks a
pinned sha256 first. `VERSION` and `TOKEN` are validated, and the token travels
over ssh stdin. The GitLab job ran with `StrictHostKeyChecking no`, so anyone
able to intercept it could feed back a forged capture; it now requires a
protected `CONFORMANCE_KNOWN_HOSTS` variable and checks strictly. Captures are
scrubbed of the oracle's identity (`oracle.example`, `192.0.2.10`,
`2001:db8::10` — documentation ranges), and the committed testdata was
anonymised the same way: a global IPv6 SAN had published the lab's ISP prefix
and, through its EUI-64 interface ID, a MAC address. See
[compatibility.md](compatibility.md).

## Live verification of 2026-10-17

The lab was rebuilt the same evening on Proxmox: one Talos v1.13.3 control
plane (Kubernetes v1.36.1), one Debian 13 worker with a stock rke2
v1.35.7+rke2r1 agent, and a throwaway rke2 server as conformance oracle. The
chart was installed by following the README quick start, from the signed
image (`cosign verify` passed first).

| Check | Result |
| --- | --- |
| `capture.sh` against the oracle | installer sha256 verified; output scrubbed; after fix 24, identical to `testdata/` |
| Agent join (`server` + `token` only) | Node Ready in 18 s; 4 certificates issued; tunnel up |
| 7 functional checks (pod↔pod both ways, ClusterIP, DNS, logs, exec, system pods) | 7/7 |
| Worker reboot | re-joined with its stored password (no 409), tunnel back, logs and exec work |
| Take over the Talos control plane by name (#1) | 409 `node already exists with no recorded node password` |
| Existing node, wrong password | 409 |
| Reserved name `kubernetes.default.svc` (#2) | 400 |
| Serving SAN `10.96.0.1` / control-plane IP / `169.254.1.1` (#3) | 400 / 400 / 400; a normal IP gets exactly `node, localhost, 127.0.0.1, ::1, <ip>` |
| RSA-1024 CSR (#5) | 400 — but the password was enrolled first: finding 22, fixed |
| Password of 1 byte (#6) | 400 |
| `system:rke2-controller` cert, obtained with the token alone (#17) | ordinary label allowed; taint, cordon, adding or removing `node-role.kubernetes.io/*` denied by the policy; Secrets and Node deletion forbidden by RBAC |
| The real agent under that policy | no denial in its log; it sets `rke2.io/node-args`, `node-config-hash`, `node-env` annotations |
| Tunnel with a non-node cert / no cert (#8) | 401 / 401 |
| Tunnel sessions for one node | 2 accepted, 3rd 429; a 64 KiB message drops the session |
| Unauthenticated `/v1-rke2/config` (#11) | 401, one WARN, rate-limited |
| Readiness probe (HTTPS `/cacerts`) and both admission policies auto-detected by the chart | as designed |

Not covered by that run: v1.31.8 agents, two control planes, an adoption, the
Cilium host policy (the lab uses Flannel), and the image signature path on a
`vX.Y.Z` tag.

## Residual risks

These remain after the audit. Each is a decision, not an oversight.

- **Live verification is partial.** One agent version, one control plane,
  Flannel; see [Live verification](#live-verification-of-2026-10-17).
- **The pod holds the cluster CA private key**, in memory and on a mounted
  Secret. Unavoidable: `serving-kubelet`, `client-kube-proxy` and
  `client-rke2-controller` have no built-in Kubernetes signer that fits, so even
  routing `client-kubelet` through the CSR API would not remove the key.
  Contained by a distroless `nonroot` image, read-only root filesystem, all
  capabilities dropped, RuntimeDefault seccomp, the key mounted `0440`. Treat
  `exec`, pod-create and Secret-read RBAC on the shim's namespace as
  cluster-admin-equivalent.
- **The shim can read every Secret in `kube-system`.** RBAC cannot scope `get`
  or `list` by name suffix, and admission never sees reads. The admission
  policy in finding 16 narrows writes only.
- **The join token is high value.** It yields new node identities and the
  shared `system:rke2-controller` identity (finding 17). Store it like a
  cluster credential, restrict `:9345` to subnets whose machines may become
  nodes, and rotate it. Rotation: update the `rke2-shim-token` Secret and
  restart the shim, which reads the file only at startup. Agents authenticate
  with the token every time `rke2-agent` starts
  ([certificates.md](certificates.md)), so a rotated token has to reach every
  worker's `/etc/rancher/rke2/config.yaml` before that worker next restarts —
  and, in a mixed pool, every real `rke2-server` must accept it too. That
  sequence is reasoned, not tested.
- **`system:rke2-controller` is shared.** Even with the admission policy, a
  token holder can change ordinary labels and annotations on any Node, and
  `nodes/status` is unrestricted.
- **Metrics are unauthenticated when enabled.** `:9346` on the host network
  exposes node names and certificate expiry. NetworkPolicy cannot protect a
  `hostNetwork` pod; use the host firewall
  ([network-security.md](network-security.md)), bind to loopback, or disable it
  with `--metrics-listen=""`.
- **`/cacerts` is unauthenticated.** Deliberate and identical to rke2: an agent
  needs the CA before it holds any credential. The response is a CA
  certificate, public by definition.
- **The Secrets-encryption override is world-readable on adopted Talos
  nodes.** `machine.files` cannot set an owner, and kube-apiserver runs as
  65534, so the file must be `0444`. Readers are host processes and `hostPath`
  pods on control-plane nodes, which can already read etcd. See
  [migration-from-rke2.md](migration-from-rke2.md#solved-override-the-encryption-config-on-the-talos-side).

## Verifying the image

Images are published to `ghcr.io/samr037/rke2-supervisor-shim`, tagged with
the commit SHA (from `main`) or `X.Y.Z` (from a `vX.Y.Z` git tag). There is no
`latest`. Each is signed keyless by the CI workflow and carries SLSA build
provenance:

```bash
TAG=0.1.0   # or a full commit SHA

cosign verify ghcr.io/samr037/rke2-supervisor-shim:$TAG \
  --certificate-identity-regexp '^https://github.com/samr037/rke2-supervisor-shim/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/samr037/rke2-supervisor-shim:$TAG \
  -R samr037/rke2-supervisor-shim
```

Then deploy by **digest**, not tag (the chart's `image.digest`), so what runs is
exactly what you verified.

## Notes for a public mirror

- `internal/nodepassword/scrypt_test.go` contains a **real node password and its
  hash**, captured from a disposable VM to prove byte-compatibility with
  upstream rke2. That cluster no longer exists. Intentional and documented in
  the test; expect a secret scanner to flag it.
- Conformance testdata now uses documentation addresses only. Manifests, docs
  and script defaults still contain the lab's RFC1918 addresses (`10.0.0.0/24`).
- `.gitignore` refuses private keys anywhere, testdata included. No key
  material, kubeconfig or API token is tracked.

## What the review found sound

- Join token compared with `subtle.ConstantTimeCompare`; node password hashes
  compared in constant time inside scrypt verification.
- **Certificate subjects are chosen by the endpoint, never read from the CSR.**
- CSR self-signatures are verified before signing.
- Issued certificates are scoped: `IsCA=false`, a single EKU (client *or*
  server), a 365-day TTL matching rke2's, now capped at the CA's expiry.
- TLS 1.2 minimum; client certificates verified against the cluster CA when
  presented.
- Node passwords are stored hashed, never in plaintext.

## Earlier audit (still in force)

Four fixes from the first review, each pinned by a test that must not be
weakened:

1. **The node password could be skipped by omitting its header**, letting a
   token holder obtain an existing node's identity. Now required on both
   node-scoped endpoints. `TestNodeCertRequiresNodePassword`. The first attempt
   at this fix was a string replacement that silently did not match; the test
   caught it. Verify fixes by test, not by inspection.
2. **A foreign cluster's IPsec PSK was committed and served** from the captured
   config. Scrubbed from testdata, stripped at serve time (`secretKeysToScrub`)
   and on capture. `TestSecretsAreScrubbedFromAgentConfig`.
3. **The tunnel accepted any client certificate the shim had issued**, because
   `TrimPrefix` returns its input unchanged when the prefix is absent. Now
   superseded by finding 8.
4. **CSR bodies were read without a firm bound.** `io.LimitReader` at 64 KiB.
   `TestCSRSizeLimit`.

Finding 1 there closed impersonation of nodes that **had** a password. Finding 1
of the 2026-10-17 audit closes it for nodes that never had one.
