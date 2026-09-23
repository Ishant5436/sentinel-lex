.PHONY: all build test clean audit

all: build test

build:
	cargo build --release

test:
	cargo test --quiet
	node --test sdk/tests/provider.test.js

audit:
	cargo audit 2>/dev/null || true

clean:
	cargo clean
