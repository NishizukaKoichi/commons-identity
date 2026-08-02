# Runbook: Local Demo

## When to use

Use this runbook to review Commons Identity with synthetic data, reproduce a bug, or verify a local change. Do not use it for a real community, real identity, production key, access-control decision, or security assurance claim.

The demo is experimental and unaudited. A successful run proves only that the checked-out code passed its local assertions.

## Prerequisites

- macOS or a supported Rust development host;
- Git;
- the Rust toolchain selected by `rust-toolchain.toml`;
- Node.js with Corepack and pnpm for the Wallet;
- Tauri native prerequisites only when running the native desktop shell.

Confirm the tools without printing environment secrets:

```sh
git --version
rustc --version
cargo --version
node --version
corepack --version
```

## Safety setup

1. Work in a disposable clone or branch.
2. Disconnect any production Credential store, browser wallet, hardware key, cloud account, or real Operator endpoint.
3. Use only the built-in `example.org`/synthetic identities.
4. Never paste a Recovery Root, `.cia` Archive, passphrase, personal name, email, or community roster into the demo.

## Procedure

From the repository root:

```sh
make setup
make check
make demo
```

`make check` is the complete local gate: format, lint, typecheck, tests, and release build for the Rust workspace and Wallet. Every command must exit successfully. A skipped or unavailable subcommand is not a pass.

`make demo` runs the CLI's synthetic lifecycle and writes only under `artifacts/demo`. It prints a randomly generated Archive passphrase once and does not store that passphrase beside the Recovery Kit or `.cia` file. Review `summary.json`; do not publish demo keys or archives as real Credentials.

To inspect the encrypted Archive inventory without displaying Vault secrets:

```sh
CI_ARCHIVE_PASSPHRASE='the passphrase printed by make demo' \
  cargo run -p commons-identity-cli -- inspect-archive \
  --archive artifacts/demo/identity-archive.cia
```

To exercise the HTTP transport profile, start the intentionally ephemeral loopback service:

```sh
cargo run -p commons-identity-service -- --demo
```

The service refuses non-demo and non-loopback operation. It generates keys and state in memory; restarting invalidates that synthetic state. This is a safety boundary, not a deployment template.

To inspect the Wallet in a browser-backed development shell:

```sh
pnpm --dir apps/wallet dev
```

Open only the loopback URL printed by the command. The screen is a reference UX. It does not imply that every displayed future feature is implemented in CI-Core.

To run the native Tauri shell after installing its platform prerequisites:

```sh
pnpm --dir apps/wallet tauri dev
```

## Expected privacy behavior

The CI-Core demo must:

- use VCDM 2.0 Context first and `eddsa-jcs-2022`;
- bind one Credential instance to one device holder key;
- disclose the complete deliberately narrow Credential;
- reject a copied Credential signed by a different holder key;
- reject replayed/expired requests and revoked/suspended Credentials;
- accept only `community` linkability and reject `none`/`verifier-domain`;
- keep different Community Persona identifiers and keys distinct;
- report stale status as unknown rather than active;
- label retention/onward-sharing as Verifier declarations, not cryptographic enforcement.
- keep Guardian Recovery absent from the binary until a reviewed implementation without known dependency advisories exists.

If the demo shows BBS selective disclosure, stable Verifier pseudonyms, or Guardian Recovery as CI-Core-complete, treat that as a defect.

## Focused verification

When diagnosing a Rust-only failure:

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

When diagnosing a Wallet-only failure:

```sh
pnpm --dir apps/wallet format:check
pnpm --dir apps/wallet lint
pnpm --dir apps/wallet typecheck
pnpm --dir apps/wallet test
pnpm --dir apps/wallet build
```

Record the commit SHA, operating system, tool versions, failing command, and first relevant error. Remove paths, tokens, and personal data before sharing logs.

## Cleanup and rollback

Stop development servers with `Ctrl-C`. The demo output is disposable and may be removed only at its explicit path:

```sh
rm -rf artifacts/demo
```

Do not delete or overwrite a real Wallet database to reset a demo. If a test unexpectedly touched data outside `artifacts/demo` or a temporary directory, stop, preserve the minimal evidence, and report it privately under [SECURITY.md](../../SECURITY.md).

## Verification record

A reproducible report contains:

```text
Commit:
OS/architecture:
Rust version:
Node/pnpm version:
make check: PASS/FAIL (no “partial pass”)
make demo: PASS/FAIL
Artifact path:
Known warnings:
```
