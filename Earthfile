VERSION 0.7
FROM golang:1.22-bookworm
WORKDIR /workspace

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...

lint:
  FROM golangci/golangci-lint:v1.57.2
  WORKDIR /workspace
  COPY . .
  RUN golangci-lint run --timeout 5m ./...

test:
  FROM +tools
  COPY go.mod go.sum .
  RUN go mod download
  COPY . .
  RUN go test -coverprofile=coverage.out -v ./...
  SAVE ARTIFACT coverage.out AS LOCAL coverage.out
  WORKDIR /workspace/tests
  WITH DOCKER
    RUN go test -timeout=300s -v ./...
  END
  WORKDIR /workspace/examples
  WITH DOCKER
    RUN for example in $(find . -name 'main.go'); do \
        go run "$example" || exit 1; \
      done
  END

tools:
  RUN apt update && apt install -y ca-certificates curl jq
  RUN curl -fsSL https://get.docker.com | bash