# GitHub Actions

`github-actions-ci.yml` belongs at `.github/workflows/ci.yml`. It is parked here
because pushing workflow files needs a token with the `workflow` scope:

```bash
gh auth refresh -s workflow
mkdir -p .github/workflows && mv ci-github/github-actions-ci.yml .github/workflows/ci.yml
git add -A && git commit -m "Add GitHub Actions CI" && git push
```

It runs `go vet`, `go test -race`, a `gofmt` check, and publishes a multi-arch
image to GHCR with ko: the commit SHA as the tag on `main`, `X.Y.Z` on a
`vX.Y.Z` tag, never `latest`. Each image is signed keyless with cosign and gets
a SLSA build-provenance attestation.

`.github/workflows/ci.yml` now exists as well. Keep the two files
byte-identical (`cmp` them) until this copy is retired; Dependabot only
updates the one under `.github/`.
