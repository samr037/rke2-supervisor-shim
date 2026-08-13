# Staying compatible with RKE2 upgrades

## The honest answer first

You **cannot** guarantee forward compatibility with the RKE2 supervisor
protocol by design. It is an internal, undocumented interface between two
halves of the same product. Rancher owes third parties nothing, ships no
specification, and has no deprecation policy for it. Anyone who tells you their
reimplementation is "compatible with future versions" is guessing.

What you *can* have — and what this repository is built around — is this:

> **You will find out that a new RKE2 version broke the shim in CI, on a
> throwaway VM, weeks before that version reaches production.**

That is a weaker promise than "compatible forever", and it is the only one that
is true. The whole design follows from taking it seriously.

## Why the risk is lower than it looks

We measured it rather than assumed it. Two real servers, four minor versions and
roughly two years apart:

| | v1.31.8+rke2r1 | v1.35.7+rke2r1 |
| --- | --- | --- |
| Endpoint set | identical | identical |
| Auth scheme (`Basic node:<token>`) | identical | identical |
| Node headers (`Rke2-Node-*`) | identical | identical |
| GET vs POST per endpoint | identical | identical |
| Which endpoints are node-scoped | identical | identical |
| Cert subjects issued | identical | identical |
| `/v1-rke2/config` keys | 64 | 65 |

The *only* schema change across four minors:

```
v1.31.8 :  ExtraSchedulerAPIArgs
v1.35.7 :  ExtraSchedulerArgs, ExtraHelmArgs
```

62 of the 63 shared keys carry byte-identical values (the exception,
`IPSECPSK`, is a per-cluster random secret). And those three keys are
server-side scheduler/helm arguments that an **agent never reads**.

So the surface an agent actually depends on has been stable across the entire
span we can test. That is not a guarantee — but it means the realistic failure
mode is a slow additive change you can absorb, not a sudden redesign.

## The three mechanisms

### 1. Build from a captured real response, not from hand-written structs

`/v1-rke2/config` is 65 keys of rke2's internal `config.Control`. The shim does
**not** hand-write them. It loads a JSON document captured from a real rke2
server (`conformance/testdata/<version>/config.json`) and overrides only the
handful of cluster-specific values.

This matters more than it looks. If RKE2 adds a field next year, an agent that
reads it gets **whatever the real server sent**, not a zero value. Hand-writing
the struct would silently send `false`/`""` for every new field — the worst kind
of bug, because it looks like it works.

Overridden keys are listed explicitly in `internal/supervisor/supervisor.go`.
Everything else is passthrough by design.

### 2. Capture the contract from a real server, per version

`conformance/capture.sh <version> <ssh-target>` installs a real rke2 server of
that exact version on a throwaway VM and records:

- the endpoint/status matrix (which paths exist, GET vs POST, which demand node headers)
- the full `/v1-rke2/config` payload
- the exact version string

into `conformance/testdata/<version>/`, which is **committed**. Upgrading RKE2
becomes a reviewable diff:

```bash
./conformance/capture.sh v1.36.3+rke2r1 debian@<throwaway-vm>
git diff conformance/testdata/
```

If that diff is empty except for the version string, the upgrade is a non-event.
If it is not empty, you are reading the exact change before it can hurt you.

### 3. Fail loudly on anything unrecognised

The shim never guesses. `handleUnknown` returns `501` and logs at ERROR:

```
UNIMPLEMENTED supervisor endpoint - possible RKE2 protocol drift  path=/v1-rke2/something-new
```

Alert on that log line. A new RKE2 version that starts calling an endpoint we
have never seen produces a loud, specific, greppable signal rather than a subtle
misbehaviour. Silence is the enemy; a 501 with a path in it is a bug report that
writes itself.

## The upgrade runbook

Before rolling any new RKE2 version to production workers:

1. `./conformance/capture.sh <new-version> <throwaway-vm>`
2. `git diff conformance/testdata/` — read it.
3. `go test ./...` — the conformance tests replay every captured contract
   against the shim's handlers. No VM required, runs in CI.
4. Join one real agent of the new version to a staging Talos cluster and
   confirm `Ready` plus pod networking.
5. Commit the new testdata directory. The version is now *supported* — meaning
   tested, not merely believed to work.

Steps 1–3 take about ten minutes. Step 4 is the one that actually proves it.

## What a breaking change would look like, and what to do

| Change | Detected by | Response |
| --- | --- | --- |
| New config key | testdata diff | usually nothing — passthrough covers it |
| Renamed config key | testdata diff | check whether agents read it; add an override if so |
| New endpoint | 501 + ERROR log, testdata diff | implement it |
| Changed auth scheme | agent fails to bootstrap, 401s in log | implement it |
| Changed cert subject | agent joins but is rejected by the Node authorizer | adjust `pki.Request` |
| Protocol redesign | everything fails at once | reassess; this is the scenario that ends the approach |

The last row is the real risk and it deserves to be stated plainly: if Rancher
rewrites agent bootstrap, this shim needs real work, and until it is done you
cannot add new RKE2 workers. Existing ones keep running — their certificates are
already issued and renew through the same endpoints — so it is an outage of
*provisioning*, not of the cluster.

## Pin your versions

Do not run `stable`. Pin the RKE2 version in your worker images or install
scripts, and only move it deliberately, through the runbook above. The shim
cannot detect an agent's version from the protocol (nothing in the handshake
carries it), so the only version control you have is the one you impose on the
fleet.

## Currently verified

| RKE2 version | Status | Captured |
| --- | --- | --- |
| v1.31.8+rke2r1 | contract captured; matches production target | yes |
| v1.35.7+rke2r1 | contract captured; agent joined a Talos cluster and reached `Ready` | yes |

Anything not in this table is unverified. That is the point of the table.
