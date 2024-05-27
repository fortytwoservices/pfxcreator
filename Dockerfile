# Build the manager binary
FROM golang:1.20 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy the entire project and download dependencies
COPY . .
RUN go mod tidy && go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager ./cmd/main.go

# Use Ubuntu as the base image
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssl ca-certificates curl gnupg lsb-release
# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

WORKDIR /

# Set a directory the non-root user can write to
RUN mkdir /.azure && chown 65532:65532 /.azure
ENV AZURE_CONFIG_DIR=/.azure

COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
