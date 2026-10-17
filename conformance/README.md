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

`config.json` is committed and also served to real agents, so `capture.sh`
scrubs it before writing: secret-shaped fields are blanked, and the oracle's
identity (`ServerNodeName` and every SAN that is not loopback, `localhost`,
`kubernetes*` or inside the service range) is replaced deterministically with
documentation values - `oracle.example`, `192.0.2.10+` (RFC 5737),
`2001:db8::10+` (RFC 3849). A global IPv6 SAN would otherwise publish the ISP
prefix and, through an EUI-64 interface ID, the VM's MAC address. Because the
mapping is positional and stable, an unchanged server re-captures
byte-identically and the drift check stays quiet.

`capture.sh` installs rke2 with the `install.sh` from the **version's git tag**,
checked against a sha256 pinned in the script before it runs as root. For a
version that is not pinned yet, review that tag's `install.sh` and either add
its digest to `install_sha256()` or pass `RKE2_INSTALL_SHA256`. `VERSION` must
match `v<maj>.<min>.<patch>+rke2r<n>`; `TOKEN` (default `conformance-token`)
must be 8-255 characters of `[A-Za-z0-9._:-]` and is sent over ssh stdin, not
on a command line.
