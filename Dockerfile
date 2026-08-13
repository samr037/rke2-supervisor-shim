FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rke2-supervisor-shim ./cmd/shim

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rke2-supervisor-shim /usr/local/bin/rke2-supervisor-shim
USER 65532:65532
EXPOSE 9345
ENTRYPOINT ["/usr/local/bin/rke2-supervisor-shim"]

# NOTE: CI publishes the image with `ko` (daemonless, cross-compiled multi-arch)
# because the shared GitLab runner cannot run a privileged dind service.
# This Dockerfile is kept for local and offline builds and produces an
# equivalent image: static binary on distroless nonroot.
