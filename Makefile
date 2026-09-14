.PHONY: check fmt lint test audit clean

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

audit:
	cargo audit

ci: fmt-check lint test audit
	@echo "CI passed"

clean:
	cargo clean
