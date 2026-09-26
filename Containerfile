# syntax=docker/dockerfile:1

# Stage 1: Build static binary
FROM golang:1.26-alpine AS builder

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
    -o /bin/legate ./cmd/legate

# Stage 2: Distroless minimal runtime
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="legate" \
      org.opencontainers.image.description="Lightweight ACME DNS-01 challenge gateway for Lego, Traefik and Caddy" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/FirPic/legate"

COPY --from=builder /bin/legate /usr/local/bin/legate

# Run as nonroot user (UID 65532)
USER nonroot:nonroot

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/legate", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/legate"]
