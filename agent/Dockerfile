# Builds static Linux binaries of the agent (no Go install needed on the host):
#   docker build -t vps-soc-agent-build agent
#   docker run --rm -v "$PWD/dist:/out" vps-soc-agent-build
FROM golang:1.23-alpine
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=0.1.0
ENV CGO_ENABLED=0 VERSION=${VERSION}
RUN go vet ./... && go test ./...
CMD for arch in amd64 arm64; do \
      GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/vps-soc-agent-linux-$arch ./cmd/vps-soc-agent || exit 1; \
    done && ls -la /out
