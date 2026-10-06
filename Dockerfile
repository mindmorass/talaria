# Single image for all talaria roles (run / send / onboard / keygen).
# Cross-compiled: the Go build runs on the BUILD platform and targets TARGETARCH,
# so multi-arch (linux/amd64 + linux/arm64) builds without QEMU-emulating the
# compiler — only the tiny final stage is per-arch.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /talaria ./cmd/talaria

FROM alpine:3.20
# ca-certificates so the runner can validate TLS to origins. On C, also mount
# the Netskope CA (see deploy/runner/docker-compose.yml) so inspected TLS
# validates inside the container's own trust store.
RUN apk add --no-cache ca-certificates && update-ca-certificates
COPY --from=build /talaria /usr/local/bin/talaria
ENTRYPOINT ["talaria"]
