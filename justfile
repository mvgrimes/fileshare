APP       := "fileshare"
VER_FILE  := "./main.go"
MAIN_FILE := "./main.go"
VERSION   := shell('perl -nE "m{version\\s*=\\s*\"(\\d+\\.\\d+\\.\\d+)\"}i && print \$1" ' + VER_FILE)
REGISTRY  := "ghcr.io/mvgrimes"
set shell := ["bash", "-euo", "pipefail", "-c"]

build:
  echo "Building verion {{VERSION}} of {{APP}}"
  go build -o {{APP}} {{MAIN_FILE}}

lint:
  go vet ./... || true
  golangci-lint run ./... || true
  govulncheck ./...

run:
	go run ./... server

migrate:
	go run ./... migrate up

run-watch: migrate
  air

fmt:
  go fmt ./...

test:
  # go test ./...
  gotestsum

generage:
  sqlc generate

release:
  go mod tidy
  just fmt
  just build
  git diff --exit-code
  git tag --points-at HEAD | grep -qx {{VERSION}} || git tag {{VERSION}}
  git push
  git release
  git push --tags
  goreleaser release --clean


deploy:
  go mod tidy
  just fmt
  git diff --exit-code
  just image-build
  git tag --points-at HEAD | grep -qx {{VERSION}} || git tag {{VERSION}}
  just image-tag
  git push
  git release
  git push --tags
  just image-push


image-build:
  GOOS=linux GOARCH=amd64 CGO_ENABLE=0 go build -o {{APP}}-linux-amd64 {{MAIN_FILE}}
  podman build -f ci/Dockerfile --platform=linux/amd64 -t mg/{{APP}} . | podman-pretty


image-tag:
  podman tag mg/{{APP}}:latest mg/{{APP}}:{{VERSION}}
  podman tag mg/{{APP}}:latest {{REGISTRY}}/{{APP}}
  podman tag mg/{{APP}}:latest {{REGISTRY}}/{{APP}}:{{VERSION}}


image-push:
  podman push {{REGISTRY}}/{{APP}}:{{VERSION}}
  podman push {{REGISTRY}}/{{APP}}:latest
