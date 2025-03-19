# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN go build -o nodekey-tools

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/nodekey-tools .

# Set the binary as the entrypoint
ENTRYPOINT ["/app/nodekey-tools"]
