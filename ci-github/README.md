# GitHub Actions

`github-actions-ci.yml` belongs at `.github/workflows/ci.yml`. It is parked here
because pushing workflow files needs a token with the `workflow` scope:

```bash
gh auth refresh -s workflow
mkdir -p .github/workflows && mv ci-github/github-actions-ci.yml .github/workflows/ci.yml
git add -A && git commit -m "Add GitHub Actions CI" && git push
```

It runs `go vet`, `go test -race`, a `gofmt` check, and publishes a multi-arch
image to GHCR with ko.
