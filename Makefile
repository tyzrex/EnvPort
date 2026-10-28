.PHONY: fmt vet test test-race build check smoke test-minio release-local security lint smoke-lan
fmt:
	gofmt -w cmd internal pkg
vet:
	go vet ./...
test:
	go test ./...
test-race:
	go test -race ./...
build:
	go build -trimpath -o bin/envport ./cmd/envport
check:
	@test -z "$$(gofmt -l cmd internal pkg)" || (gofmt -l cmd internal pkg; exit 1)
	go vet ./...
	go test ./...
smoke: build
	python3 scripts/smoke.py
smoke-lan: build
	python3 scripts/smoke_lan.py
test-minio:
	python3 scripts/test_minio.py
release-local:
	python3 scripts/build_release.py
security:
	govulncheck ./...
	python3 scripts/check_secrets.py
lint:
	staticcheck ./...
