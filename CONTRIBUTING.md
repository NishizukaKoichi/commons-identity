# Contributing to Commons Identity

Thank you for helping build a holder-controlled, community-scoped identity protocol. The most valuable contributions make a claim more testable, reduce privacy risk, or expose a limit honestly.

The project is a Developer Preview and unaudited. Do not use real identities, production keys, private community records, or third-party systems while developing.

## Before you start

Read:

- [Protocol Specification](docs/specification/commons-identity-1.0.ja.md)
- [Context Snapshot](docs/context-snapshot.md)
- [Threat Model](docs/threat-model.md)
- [Governance](docs/governance.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

Security vulnerabilities go through the private process in [SECURITY.md](SECURITY.md), not a public Issue.

## Choose the smallest useful change

- **Bug fix:** link the failing test or add one first.
- **Protocol change:** identify the affected section, privacy impact, compatibility, alternative, and migration.
- **New cryptography/profile:** open a design Issue and ADR before implementation; include primary specifications and independent vectors.
- **Documentation:** state whether wording is normative or informative and cite primary sources for standards status.
- **UX:** include keyboard, screen-reader, plain-language consent, and false-assurance checks.

Avoid unrelated cleanup in the same Pull Request. A change to identifiers, cryptosuites, Contexts, Schemas, Archive format, recovery, auth, file/network I/O, or dependencies requires an explicit risk and rollback note.

## Local setup

The repository pins its Rust toolchain. The Wallet also needs a current Node.js runtime with Corepack/pnpm and the native prerequisites required by Tauri on your operating system.

```sh
git clone https://github.com/NishizukaKoichi/commons-identity.git
cd commons-identity
make setup
make check
```

For the synthetic local flow:

```sh
make demo
```

See the [Local Demo Runbook](docs/runbooks/local-demo.md) for prerequisites, expected results, and cleanup.

Useful focused checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo build --workspace --all-features --release
```

Run the narrowest test while iterating, then `make check` before requesting review. If a required check cannot run on your platform, say exactly which check, why, and what evidence you do have; do not mark it passed.

## Protocol contribution requirements

A normative change must include:

1. a minimal specification diff with MUST/MUST NOT behavior;
2. an ADR for a material decision;
3. positive and negative test vectors;
4. privacy and cross-community correlation analysis;
5. downgrade, replay, stale-state, and malformed-input behavior;
6. compatibility and migration plan;
7. primary-source standards references with version/date;
8. CHANGELOG entry.

CI-Core is specifically `application/vc` + `application/vp`, VCDM 2.0, and `eddsa-jcs-2022`. Do not call it generic `ldp_vc` interoperability. CI-Core rejects `linkability:none` and `verifier-domain`; do not weaken the check or the UI warning to make a demo pass.

## Pull Request checklist

- [ ] The change is scoped and has no unrelated refactor.
- [ ] No secrets, Recovery Kits, real Credentials, personal data, generated database, or build artifact is committed.
- [ ] Behavior changes have tests, including failure paths.
- [ ] `make check` is green, or each unavailable gate is disclosed accurately.
- [ ] Security/privacy assumptions and residual risk are documented.
- [ ] Medium-impact decisions include alternatives and rollback.
- [ ] Normative changes update the specification, ADR as needed, and CHANGELOG.
- [ ] New dependencies have purpose, maintenance, license, and supply-chain review.
- [ ] User-facing consent text states what is actually guaranteed.
- [ ] Documentation links and examples are checked.

## Commits and review

Use focused, imperative commit messages such as `Document CI-Core issuer binding`. Reviewers may ask for a split when a diff mixes behavior, restructuring, generated artifacts, or unrelated documentation.

Maintainers merge based on evidence and the process in [Governance](docs/governance.md). A passing test does not override the twelve protocol principles.

## Licensing contributions

Unless you explicitly state otherwise, an intentional contribution is submitted under the license mapped to its destination:

- code, tests, configuration, and machine-readable examples: Apache-2.0;
- prose documentation: CC BY 4.0.

See [LICENSES/README.md](LICENSES/README.md). Do not submit material you lack the right to license. Preserve third-party notices and clearly mark adapted content.

## Need help?

Open a public Issue with a narrow question and links to the relevant file/section. Never include a vulnerability, secret, or personal identity record.
