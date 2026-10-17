# Security policy

rke2-supervisor-shim holds the cluster CA private key and signs node
certificates, so security reports are taken seriously.

## Reporting a vulnerability

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/samr037/rke2-supervisor-shim/security/advisories/new)**.
Do not open a public issue for anything exploitable.

Include the shim version (image tag or digest), the rke2 and Talos versions,
and the request sequence or configuration needed to reproduce.

## Supported versions

Only the latest release and `main` receive fixes.

## What is already documented

[docs/security.md](docs/security.md) records the threat model, every finding of
the 2026-10-17 audit with its fix and test, and the residual risks that are
accepted on purpose (for example: the join token is node-admin grade, and reads
of `kube-system` Secrets cannot be narrowed by admission). Reports about those
are still welcome if you find a way to make them worse than described.

## Verifying images

Release images are signed with cosign (keyless, GitHub OIDC) and carry SLSA
build provenance. See the README for the `cosign verify` and
`gh attestation verify` commands.
