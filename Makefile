.PHONY: setup fmt lint typecheck test build check demo

setup:
	corepack enable
	pnpm --dir apps/wallet install --frozen-lockfile

fmt:
	cargo fmt --all
	pnpm --dir apps/wallet format

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	pnpm --dir apps/wallet lint

typecheck:
	cargo check --workspace --all-targets --all-features
	pnpm --dir apps/wallet typecheck

test:
	cargo test --workspace --all-features
	pnpm --dir apps/wallet test

build:
	cargo build --workspace --all-features --release
	pnpm --dir apps/wallet build

check: fmt lint typecheck test build

demo:
	cargo run -p commons-identity-cli -- demo --output artifacts/demo
