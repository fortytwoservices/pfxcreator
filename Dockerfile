# Build the manager binary
FROM golang:1.20 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy the entire project
# Ensure that your .dockerignore file is configured to exclude unnecessary files
COPY . .

# Download dependencies - this uses the go.mod and go.sum files
RUN go mod tidy && go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager ./cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
