set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

binary := "bin/pwned"
go_cache := "$(pwd)/.cache/go-build"
go_mod_cache := "$(pwd)/.cache/go-mod"

prepare:
    mkdir -p bin {{go_cache}} {{go_mod_cache}}

build: prepare
    GOCACHE={{go_cache}} GOMODCACHE={{go_mod_cache}} go build -o {{binary}} ./cmd/pwned

test: prepare
    GOCACHE={{go_cache}} GOMODCACHE={{go_mod_cache}} go test ./...

fmt:
    gofmt -w $(find cmd internal -name '*.go' -type f)

tidy: prepare
    GOCACHE={{go_cache}} GOMODCACHE={{go_mod_cache}} go mod tidy

run-help: build
    ./{{binary}} help

clean:
    rm -rf bin .cache .state

infra-start:
    docker compose up -d

infra-stop:
    docker compose down

infra-clean: infra-stop
    rm -rf qwdata
