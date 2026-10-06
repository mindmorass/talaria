# Single image for all talaria roles (run / send / onboard / keygen).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /talaria ./cmd/talaria

FROM alpine:3.20
# ca-certificates so the runner can validate TLS to origins. On C, also mount
# the Netskope CA (see deploy/runner/docker-compose.yml) so inspected TLS
# validates inside the container's own trust store.
RUN apk add --no-cache ca-certificates && update-ca-certificates
COPY --from=build /talaria /usr/local/bin/talaria
ENTRYPOINT ["talaria"]
