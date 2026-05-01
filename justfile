APP       := "sharefile"
VER_FILE  := "./main.go"
MAIN_FILE := "./main.go"
VERSION   := shell('perl -nE "m{version\\s*=\\s*\"(\\d+\\.\\d+\\.\\d+)\"}i && print \$1" ' + VER_FILE)

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
  go test ./...

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
