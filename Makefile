# Makefile
.PHONY: build-linux-amd64 build-linux-arm64 build

build-linux-amd64:
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-o bin/golinhound-linux-amd64 \
	./cmd/golinhound

build-linux-arm64:
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
	-o bin/golinhound-linux-arm64 \
	./cmd/golinhound

build: build-linux-amd64 build-linux-arm64
