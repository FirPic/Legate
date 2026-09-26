FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mock-cf main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mock-cf /usr/local/bin/mock-cf
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mock-cf"]
