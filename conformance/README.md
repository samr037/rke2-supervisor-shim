# Conformance

Two tiers, described fully in [../docs/compatibility.md](../docs/compatibility.md).

**Tier 1 — every commit, no infrastructure.** `go test ./...` replays the
contracts committed under `testdata/` against the shim's handlers.

**Tier 2 — scheduled, needs a throwaway VM.** `capture.sh <version> <ssh-target>`
installs a real rke2 server of that version and re-records its contract. CI runs
it nightly and fails on any diff, so upstream protocol drift surfaces before an
upgrade reaches production.

```bash
./capture.sh v1.36.3+rke2r1 user@rke2-server
git diff testdata/
```

`testdata/<version>/` holds `config.json` (the full /v1-rke2/config payload),
`endpoints.txt` (the endpoint/status matrix) and `version.txt`.
