# syntax=docker/dockerfile:1

# Stage 1: Build static binary
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.0.0
ARG COMMIT=dev
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.Date=${DATE}" \
    -o /bin/acme-dns-proxy ./cmd/acme-dns-proxy

# Stage 2: Distroless minimal runtime
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="acme-dns-httpreq-proxy" \
      org.opencontainers.image.description="Secure, lightweight ACME DNS-01 HTTP proxy for Lego and Traefik" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/FirPic/acme-dns-httpreq-proxy"

COPY --from=builder /bin/acme-dns-proxy /usr/local/bin/acme-dns-proxy

# Run as nonroot user (UID 65532)
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/acme-dns-proxy"]
