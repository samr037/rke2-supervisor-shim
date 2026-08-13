# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this is

A Go service that speaks the **RKE2 supervisor protocol** (port 9345) backed by
a **Talos** control plane, so stock `rke2 agent` nodes can join a Talos-managed
Kubernetes cluster. It exists because `rke2 agent` refuses Kubernetes' standard
kubelet TLS bootstrap and `rke2 server` cannot be reduced to a supervisor.

Read [docs/architecture.md](docs/architecture.md) before changing anything.

## The single most important rule

**The RKE2 supervisor protocol is undocumented and reverse-engineered. Never
guess at it. Capture it.**

Every protocol fact in this repo came from proxying a real `rke2 agent` through
a logging MITM to a real `rke2 server`. If you need to know how something
behaves, reproduce that setup — do not infer it from k3s source, and do not
assume symmetry with anything.

Facts that were counter-intuitive and cost real time:

| Assumption | Reality |
| --- | --- |
| headers are `K3s-*` | they are `Rke2-*` |
| cert endpoints are GET | they are **POST**; GET returns a misleading `400 "node name not set"` |
| all cert endpoints are node-scoped | `client-kube-proxy` and `client-rke2-controller` carry **no** node headers |
| the tunnel authenticates like everything else | it sends **no** `Authorization` header at all — it is mTLS |
| `EgressSelectorMode: disabled` stops the tunnel | it does not; the agent connects unconditionally |

## Conventions

- **Verify by test, not by inspection.** A security fix in this repo was once
  applied by a string replacement that silently did not match, leaving the
  vulnerability in place. The regression test caught it. Add the test first.
- **Report honestly.** If something is untested, say "untested". The README and
  docs distinguish *captured*, *verified*, and *believed* — keep that.
- **Re-test a finding before building on it, especially a negative one.**
  `docs/risk-register.md` item 4 claimed RKE2 apiservers could not reach migrated
  workers and called it unfixable. It was diagnosed against a kubelet still
  holding a certificate issued *before* the fix that was being evaluated. A clean
  re-registration disproved it. "X is impossible" is the most expensive kind of
  claim to get wrong, because nobody re-checks it — so state the evidence and the
  date, and re-run it before it becomes a design constraint.
- **Never hand-write a Talos machine config for an adopted cluster.** Run
  `examples/adopt-rke2-cluster/preflight.sh`. Every parameter it checks is one
  Talos will otherwise default to something plausible and wrong, often failing
  late, intermittently, or only after a leader election.
- Comments explain **why**, never what. Assume the reader can read Go.
- Never hand-write the agent config. It is a captured payload plus a small
  override list — see `buildAgentConfig`.
- Anything unrecognised must fail loudly (501 + ERROR log), never be guessed.

## Layout

```
cmd/shim/              entrypoint: flags, TLS, tunnel wiring
internal/supervisor/   the protocol: routes, auth, agent config, issuance
internal/pki/          CSR validation and signing with the cluster CA
internal/nodepassword/ scrypt (rke2-compatible) + Secret-backed store
internal/certs/        the shim's own self-issued, auto-rotated serving cert
internal/expiry/       expiry annotations, warning events, Prometheus metrics
conformance/           capture.sh + committed per-version protocol contracts
deploy/                Kubernetes manifests (hostNetwork, control-plane node)
docs/                  architecture, protocol, compatibility, certificates, security
```

## Testing

```bash
go test ./...        # no cluster or VM required; gates every merge
go vet ./...
gofmt -l .
```

Tier 1 tests replay contracts captured from real rke2 servers under
`conformance/testdata/<version>/`. Tier 2 (`conformance/capture.sh`) needs a
throwaway VM and re-records those contracts; CI runs it on a schedule and fails
on any diff. See [docs/compatibility.md](docs/compatibility.md).

**Do not weaken these tests to make a change pass.** They encode protocol facts
and two security fixes:
- `TestNodeCertRequiresNodePassword` — node impersonation
- `TestSecretsAreScrubbedFromAgentConfig` — a foreign cluster's IPsec PSK leaking
- `TestVerifyRealRKE2Hash` — byte-compatibility with rke2's password hashing

## Security posture

This process **signs certificates with the Kubernetes cluster CA**. It is part
of the control plane's trust boundary. Before touching `internal/pki` or
`internal/supervisor`, read [docs/security.md](docs/security.md).

Non-negotiable invariants:

1. Certificate subjects are decided by the endpoint, **never** read from the CSR.
2. The node password is **required** on node-scoped endpoints, not optional.
3. Nothing secret-shaped from the captured config template is forwarded to
   agents (`secretKeysToScrub`).
4. The token is compared in constant time.
5. Never log a token, a node password, or private key material.

## Environment

Development happens against a maquette on Proxmox (`pve2`, `10.0.0.220`):

| Host | Role |
| --- | --- |
| `10.0.0.245` | Talos control plane, runs the shim |
| `10.0.0.246` | Debian worker, plain kubelet |
| `10.0.0.249` | Debian worker, stock rke2 agent |
| `10.0.0.251` | throwaway rke2 **server**, the conformance oracle |

These addresses appear in `deploy/shim.yaml` and `conformance/capture.sh` as
defaults. They are examples, not requirements.

CI publishes a multi-arch image with **ko** (not buildx: the shared runner has no
privileged dind, and ko cross-compiles Go natively instead of emulating arm64).
`ko` requires Go ≥ 1.26.3.

## Known gaps — do not "fix" silently

- The pod holds the cluster CA private key. Unavoidable; see security.md.
- Metrics on `:9346` are unauthenticated on the host network.
- CA rotation is a documented manual runbook, deliberately not automated.
- Expiry warnings are verified only synthetically, never by a genuinely aged
  certificate.
