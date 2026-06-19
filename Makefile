.PHONY: check fmt lint test clean

check:
	cargo check --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-features -- -D warnings

test:
	cargo test --workspace

ci: fmt-check lint test
	@echo "CI passed"

clean:
	cargo clean
