
build-all:
	go build -o ./check-all ./cmd/check-all/...
	go build -o ./tcp-send ./cmd/tcp-send/...
	go build -o ./ipip-send ./cmd/ipip-send/...
	go build -o ./capture-packet ./cmd/capture-packet/...
clean:
	rm ./check-all ./tcp-send ./ipip-send ./capture-packet || true