# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Copy go module files
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary with security hardening flags
ARG VERSION=1.0.0
ARG COMMIT=dev
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.Date=${DATE}" \
    -o /bin/acme-dns-httpreq-proxy ./cmd/server

# Final stage: Distroless-style minimal scratch container with CA certificates
FROM alpine:3.21 AS certs
RUN apk --no-cache add ca-certificates tzdata

FROM scratch

# Import CA certificates for HTTPS calls to Cloudflare
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=certs /usr/share/zoneinfo /usr/share/zoneinfo

# Import binary
COPY --from=builder /bin/acme-dns-httpreq-proxy /acme-dns-httpreq-proxy

# Use non-root user (nobody:nobody)
USER 65534:65534

# Standard ACME httpreq proxy port
EXPOSE 8080

ENTRYPOINT ["/acme-dns-httpreq-proxy"]
