ARG GO_VERSION=1.24

### ---- build stage ----
FROM golang:${GO_VERSION}-bookworm AS builder

# Build dependencies (including librdkafka headers)
RUN apt-get update && apt-get install -y \
    curl gnupg build-essential librdkafka-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with CGO enabled (required by confluent-kafka-go)
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

RUN go build -o /app/enrich-soc ./cmd

### ---- runtime stage ----
FROM debian:bookworm-slim

# Runtime dependencies (librdkafka shared library, certs, tzdata)
RUN apt-get update && apt-get install -y \
    ca-certificates tzdata librdkafka1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/enrich-soc /usr/local/bin/enrich-soc

# Optional: non-root user (comment out if you prefer root)
# RUN useradd -m appuser
# USER appuser

ENV TZ=UTC

ENTRYPOINT ["/usr/local/bin/enrich-soc"]
CMD []