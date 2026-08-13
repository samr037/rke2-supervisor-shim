# Security audit

Reviewed: the full Go source, deployment manifests, CI, and every tracked file
for committed credentials. Four issues were found and fixed; four are accepted
risks that you should know about.

This component signs certificates with the cluster CA. Treat it as part of the
control plane's trust boundary, not as an ordinary workload.

## Fixed

### 1. Node password could be bypassed entirely — high

`handleCert` verified the node password *only when the header was present*:

```go
if pw := r.Header.Get(hdrNodePassword); pw != "" && s.pw != nil { ... }
```

Omitting `Rke2-Node-Password` skipped the check. Anyone holding the join token
could therefore request `client-kubelet.crt` for **an existing node's name** and
receive a valid `O=system:nodes, CN=system:node:<victim>` certificate — a full
node impersonation, and precisely what node passwords exist to prevent.

The token alone is not sufficient authorisation here: in rke2's model the token
lets you join *a* node, while the node password stops you from becoming *another*
node.

Fixed by requiring the header on both node-scoped endpoints. Pinned by
`TestNodeCertRequiresNodePassword`.

> Worth noting how this was caught: the first attempt to fix it was applied with
> a string replacement that silently did not match, and the code was left
> vulnerable. The regression test is what surfaced that — it returned 500
> (reached signing) instead of 400. Verify fixes by test, not by inspection.

### 2. A foreign cluster's IPsec PSK was committed and served — medium

`/v1-rke2/config` is served from a capture taken on a throwaway rke2 server, and
that payload contains `IPSECPSK`, a pre-shared key belonging to that cluster.
It was both committed to git under `conformance/testdata/` and relayed verbatim
to every joining agent.

Nothing uses IPsec here (`FlannelBackend` is `none`), so this was key material
travelling for no reason. Fixed three ways: scrubbed from the committed
testdata, stripped at serve time via `secretKeysToScrub`, and `capture.sh` now
scrubs on capture so it cannot come back. Pinned by
`TestSecretsAreScrubbedFromAgentConfig`, which re-injects the key and asserts it
does not reach the agent.

### 3. Tunnel accepted any client certificate we had issued — medium

The remotedialer authorizer derived a node name with
`strings.TrimPrefix(cn, "system:node:")`. `TrimPrefix` returns the string
unchanged when the prefix is absent, so a `system:kube-proxy` or
`system:rke2-controller` certificate — both of which the shim hands out — could
open a tunnel session registered under its own CN as though it were a node.

Fixed by requiring the `system:node:` prefix and rejecting anything else.

### 4. Request body read without a firm bound — low

`readCSR` looped over `Body.Read`, appended before checking the size, and
discarded non-EOF errors. Replaced with `io.LimitReader` at 64 KiB (a DER CSR is
about 200 bytes) and proper error propagation. Pinned by `TestCSRSizeLimit`.

## Accepted risks

### The pod holds the cluster CA private key

Compromising this pod compromises the cluster: the key signs any Kubernetes
identity. This is inherent to the design — the shim's whole job is to issue
certificates rke2 agents will trust.

Routing `client-kubelet` through the Kubernetes CSR API would avoid holding the
key for that one case, but `serving-kubelet`, `client-kube-proxy` and
`client-rke2-controller` have no built-in signer that fits, so the key would
have to stay regardless.

Mitigations in place: distroless `nonroot` image, `readOnlyRootFilesystem`, all
capabilities dropped, no privilege escalation, the key mounted `0440` and only
readable by the runtime user, and RBAC limited to `get`/`create`/`patch`/`list`
on Secrets in `kube-system` plus event creation. Consider a dedicated
control-plane node and restricting who can `exec` into `rke2-shim`.

### Metrics are exposed on the host network

`:9346/metrics` binds on a `hostNetwork` pod, so it is reachable from anywhere
that can route to the control-plane node, unauthenticated. It exposes node names
and certificate expiry timestamps — no key material, but it is reconnaissance.
NetworkPolicy does not apply to `hostNetwork` pods; restrict it at the firewall,
or move it with `--metrics-listen`.

### `/cacerts` is unauthenticated

Deliberate, and identical to a real rke2 server: an agent must fetch the CA
before it possesses any credential. The response is a CA *certificate* — public
by definition.

### The join token grants node enrolment

Anyone with the token can enrol a *new* node (they cannot take over an existing
one — see finding 1). This is rke2's model, not something the shim weakens.
Rotate the token by updating the `rke2-shim-token` Secret and restarting the
shim; existing nodes are unaffected because they already hold certificates.

## Notes for a public mirror

* `internal/nodepassword/scrypt_test.go` contains a **real node password and its
  hash**, captured from a disposable VM specifically to prove byte-compatibility
  with upstream rke2. The cluster no longer exists. Intentional, and documented
  in the test, but expect a secret scanner to flag it.
* Manifests, docs and `conformance/capture.sh` contain private RFC1918 addresses
  (`10.0.0.0/24`) and internal hostnames. Harmless, but it is internal
  topology; genericise before publishing if that matters to you.
* No key material, kubeconfig or API token is tracked in git — verified.

## What the review found to be sound

- Join token compared with `subtle.ConstantTimeCompare`; node password hashes
  compared in constant time inside scrypt verification.
- **Certificate subjects are chosen by the endpoint, never taken from the CSR**,
  so an agent cannot request an arbitrary identity by crafting one.
- CSR self-signatures are verified before signing.
- Issued certificates are strictly scoped: `BasicConstraintsValid`, `IsCA=false`,
  a single EKU (client *or* server), and a 365-day TTL matching rke2's.
- TLS floor of 1.2; client certificates verified against the cluster CA when
  presented.
- Unknown endpoints return 501 and log at ERROR rather than guessing.
- Node passwords are trust-on-first-use, stored hashed, never in plaintext.
