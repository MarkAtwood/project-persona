.PHONY: check portability fmt lint test audit clean

check:
	cargo check --workspace

# Type-checks the targets no local `cargo check` reaches. On Linux the
# #[cfg(target_os = "macos")] arms are never compiled, so a type error in one
# is invisible until CI's macOS leg runs; this catches it here.
# Mirrors the CI portability job, so `make ci` covers what CI covers.
# Needs: rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin \
#          aarch64-unknown-linux-ohos
portability:
	cargo check --target x86_64-pc-windows-msvc -p persona-core
	cargo check --target aarch64-apple-darwin -p persona-core
	cargo check --target aarch64-unknown-linux-ohos -p persona-core
	cargo check --target aarch64-apple-darwin --workspace

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

ci: fmt-check lint test audit portability
	@echo "CI passed"

clean:
	cargo clean
