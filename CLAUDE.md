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
- Anything unrecognised must fail loudly (501 + ERROR log), never be guessed —
  for **authenticated** requests. Unauthenticated ones get a quiet 401 so a
  scanner cannot bury the drift signal; keep that ordering.
- **Do not inflate verification claims.** The lab VMs are gone. Everything
  from the 2026-10-17 security audit is unit-tested or reviewed, not run
  against a real rke2 agent; say so wherever it matters until someone re-runs
  it live.

## Layout

```
cmd/shim/              entrypoint: flags, token resolution, TLS, server limits
internal/supervisor/   the protocol: routes, auth, agent config, issuance,
                       node-name / SAN validation
internal/pki/          CSR validation (key policy) and signing with the cluster CA
internal/nodepassword/ scrypt (rke2-compatible, bounded) + Secret-backed store
internal/tunnel/       /v1-rke2/connect: remotedialer behind node-identity,
                       session and message-size limits
internal/apiservers/   control-plane discovery for /v1-rke2/apiservers
internal/certs/        the shim's own self-issued, auto-rotated serving cert
internal/expiry/       expiry annotations, warning events, Prometheus metrics
conformance/           capture.sh + committed per-version protocol contracts
charts/                Helm chart (DaemonSet, RBAC, admission policies, schema)
deploy/                raw manifests, admission policies, host firewalls
examples/              RKE2 adoption scripts, kube-vip manifests
hack/loadgen/          bootstrap load generator (see docs/benchmarks.md)
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
and security fixes. The ones that matter most:
- `TestNodeCertRequiresNodePassword` — node impersonation
- `TestExistingNodeWithoutPasswordIsAConflict`,
  `TestCheckAndSetRefusesExistingNodeWithoutPassword` — taking over a node that
  never enrolled (every Talos control plane)
- `TestCheckAndSetAcceptsAdoptedRKE2Node` — adopted workers must keep passing
- `TestNodeNameIsValidated`, `TestServingCertSANIPsAreRestricted` — what a
  token holder can get a certificate *for*
- `TestUsageNeverContainsTheToken` — the token leaking through `-h`
- `TestAuthorizeRequiresNodeIdentity`, `TestTunnelSessionsPerNodeAreCapped`,
  `TestTunnelMessageSizeIsCapped` — tunnel identity and limits
- `TestSecretsAreScrubbedFromAgentConfig` — a foreign cluster's IPsec PSK leaking
- `TestVerifyRealRKE2Hash` — byte-compatibility with rke2's password hashing

The full list, per finding, is in [docs/security.md](docs/security.md).

## Security posture

This process **signs certificates with the Kubernetes cluster CA**. It is part
of the control plane's trust boundary. Before touching `internal/pki` or
`internal/supervisor`, read [docs/security.md](docs/security.md).

Non-negotiable invariants:

1. Certificate subjects are decided by the endpoint, **never** read from the CSR.
2. The node password is **required** on node-scoped endpoints, not optional,
   and missing wiring fails closed.
3. Trust-on-first-use applies only to names that are not already a Node.
   A Node with no `<node>.node-password.rke2` Secret gets 409, never enrolment.
4. Everything the client chooses that lands in a certificate is validated:
   node name (DNS-1123, deny list), `Rke2-Node-Ip` SANs, CSR key type and size.
5. Nothing secret-shaped from the captured config template is forwarded to
   agents (`secretKeysToScrub`).
6. The token is compared in constant time, read from `--token-file` in every
   shipped manifest, and never a flag default (flag defaults are printed by
   `-h`).
7. Never log a token, a node password, or private key material.
8. Tunnel sessions require `CN=system:node:<n>` **and** `O=system:nodes`; at
   most 2 per node; websocket messages over 16 KiB drop the session.
   remotedialer has no limits of its own — do not remove the wrapper in
   `internal/tunnel`.

## Environment

Development happens against a maquette on Proxmox (`pve2`, `10.0.0.220`). The
original one was destroyed; it was rebuilt on 2026-10-17 to live-verify the
audit (docs/security.md, "Live verification"). It is disposable: check it
exists before relying on it.

| Host | Role |
| --- | --- |
| `10.0.0.245` | Talos control plane, runs the shim |
| `10.0.0.246` | Debian worker, plain kubelet |
| `10.0.0.249` | Debian worker, stock rke2 agent |
| `10.0.0.251` | throwaway rke2 **server**, the conformance oracle |

These addresses appear in `deploy/shim.yaml` and `conformance/capture.sh` as
defaults. They are examples, not requirements.

## Release flow

CI publishes a multi-arch image with **ko** (not buildx: the shared runner has no
privileged dind, and ko cross-compiles Go natively instead of emulating arm64).
`ko` requires Go ≥ 1.26.3.

- `main` publishes `ghcr.io/samr037/rke2-supervisor-shim:<commit-sha>`; a
  `vX.Y.Z` git tag publishes `:X.Y.Z`. **Nothing publishes `latest`**, and the
  chart schema rejects it. Never reintroduce a moving tag: the image receives
  the cluster CA key.
- Each image is signed keyless with cosign (by digest) and gets SLSA build
  provenance. Verification commands: docs/security.md.
- To release: bump `version` and `appVersion` in `Chart.yaml` and the tag in
  `deploy/shim.yaml`, then push `vX.Y.Z`. Other tag names are refused by CI.
- Actions are pinned by commit SHA; Dependabot bumps them, Go modules and the
  Dockerfile digests. It **cannot see `.ko.yaml`**: when it bumps the
  distroless digest in `Dockerfile`, update `defaultBaseImage` in `.ko.yaml` to
  the same digest in the same PR (ko is what CI actually builds with). The ko
  version in `ci.yml` and `.gitlab-ci.yml` is also bumped by hand.
- `ci-github/github-actions-ci.yml` must stay byte-identical to
  `.github/workflows/ci.yml`.
- The GitLab conformance job needs the protected `CONFORMANCE_KNOWN_HOSTS`
  variable; it refuses to run without it.

## Known gaps — do not "fix" silently

- The pod holds the cluster CA private key. Unavoidable; see security.md.
- The shim's ServiceAccount can read every Secret in `kube-system`; admission
  policy narrows writes only.
- `system:rke2-controller` is issued to any token holder and shared by every
  agent. Our ClusterRole grants node `patch`/`update` (upstream rke2 grants only
  `get`); an admission policy limits it to labels/annotations and leaves
  `nodes/status` open. Re-capture what the agent writes before narrowing.
- Metrics on `:9346` are unauthenticated on the host network when enabled.
- CA rotation is a documented manual runbook, deliberately not automated.
- Expiry warnings are verified only synthetically, never by a genuinely aged
  certificate.
