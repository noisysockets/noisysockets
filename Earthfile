VERSION 0.7
FROM golang:1.21-bookworm
WORKDIR /workspace

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...

lint:
  FROM golangci/golangci-lint:v1.55.2
  WORKDIR /workspace
  COPY . .
  RUN golangci-lint run --timeout 5m ./...

test:
  FROM +tools
  COPY go.mod go.sum .
  RUN go mod download
  COPY . .
  WITH DOCKER
    RUN go test -timeout=120s -coverprofile=coverage.out -v ./...
  END
  SAVE ARTIFACT coverage.out AS LOCAL coverage.out

tools:
  RUN apt update && apt install -y ca-certificates curl jq
  RUN curl -fsSL https://get.docker.com | bash