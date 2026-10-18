# Base images are pinned by digest so a rebuild cannot silently pick up a
# different toolchain or runtime; Dependabot proposes digest bumps. Keep the
# runtime digest equal to defaultBaseImage in .ko.yaml (the CI build path).
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rke2-supervisor-shim ./cmd/shim

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/rke2-supervisor-shim /usr/local/bin/rke2-supervisor-shim
USER 65532:65532
EXPOSE 9345
ENTRYPOINT ["/usr/local/bin/rke2-supervisor-shim"]

# NOTE: CI publishes the image with `ko` (daemonless, cross-compiled multi-arch)
# because the shared GitLab runner cannot run a privileged dind service.
# This Dockerfile is kept for local and offline builds and produces an
# equivalent image: static binary on distroless nonroot.
