VERSION 0.7
FROM golang:1.22-bookworm
WORKDIR /workspace

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...
  RUN for dir in $(find . -name 'go.mod'); do \
      (cd "${dir%/go.mod}" && go mod tidy); \
    done

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
  WORKDIR /workspace/test
  WITH DOCKER
    RUN go test -timeout=300s -v ./...
  END
  WORKDIR /workspace/examples
  WITH DOCKER
    RUN --privileged for example in $(find . -name 'main.go'); do \
        go run "$example" || exit 1; \
      done
  END

examples:
  COPY go.mod go.sum .
  RUN go mod download
  COPY . .
  RUN mkdir /workspace/dist
  WORKDIR /workspace/examples
  RUN for example in $(find . -name 'main.go'); do \
      (cd "${example%/main.go}" && go build -o "/workspace/dist/${example%/main.go}" .); \
    done
  SAVE ARTIFACT /workspace/dist AS LOCAL dist

tools:
  RUN apt update && apt install -y ca-certificates curl jq
  RUN curl -fsSL https://get.docker.com | bash