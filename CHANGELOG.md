# Changelog

All notable changes to Commons Identity are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before `1.0.0`, compatibility may change; every breaking protocol/profile change still requires a new identifier or explicit migration rather than silent reinterpretation.

## [Unreleased]

## [0.1.0-preview.2] - 2026-08-03

### Fixed

- Classified Tauri's Linux target capability schema as a generated build artifact so the immutable release clean-tree gate remains strict without rejecting a successful clean-runner build.
- Made the release clean-tree gate print every unexpected path before failing, preserving actionable audit evidence.
- Added the same clean-tree assertion to normal Linux CI so generated-file regressions fail before a version tag is created.

### Release provenance

- Preserved `v0.1.0-preview.1` as an unchanged annotated tag and protected `v*` tags from update or deletion. Its [release workflow](https://github.com/NishizukaKoichi/commons-identity/actions/runs/30753405849) passed all Rust, dependency, and Wallet gates, then stopped at the clean-tree gate before artifact assembly or publication; no distributable `preview.1` assets were published.
- Enabled GitHub Immutable Releases and changed publication to draft, complete asset upload, remote tag-object/commit revalidation, then immutable publication.

## [0.1.0-preview.1] - 2026-08-03

### Added

- Initial `commons-identity/1` Developer Preview specification with all 36 design sections.
- CI-Core boundary for VCDM 2.0 `application/vc` and `application/vp` using `eddsa-jcs-2022`.
- Public OSS governance, threat model, security policy, contribution guide, licensing map, and operational runbooks.
- Machine-readable Commons Identity Context v1 vocabulary snapshot.
- Rust CI-Core primitives, local HTTP issuance/presentation service, conformance CLI, and a Tauri Wallet UX preview.
- End-to-end tests for holder-bound issuance, signed OID4VP requests, replay rejection, per-device revocation, status enforcement, encrypted Archive round trips, and staged Operator Migration.

### Security

- Marked the reference implementation experimental and unaudited.
- Required signed issuer-to-Community Authority binding, holder-key proof matching, signed `ci_request` fail-closed behavior, and separate revocation/suspension status handling.
- Explicitly excluded CI-Private-BBS and Guardian Recovery from CI-Core conformance.
- Removed the experimental `sharks` Guardian implementation and dependency after identifying RUSTSEC-2024-0398; Guardian Recovery is not shipped.
- Replaced migration approval labels with 3-of-5 Ed25519 controller signatures, bound registry encryption to community/source/target with HKDF-SHA-256, and made import validation stage-only.
- Restricted the stateful HTTP reference service to an ephemeral loopback demo until durable keys/state, external identity proofing, and an independent audit exist.
- Required Wallet credential ingestion to verify issuer authorization, proof, validity, holder binding, community, and signed status references.
- Required five distinct governance keys, exact Authority DID/key verification methods, collision-free persona-device bindings, bounded credential-instance registries, and fail-closed future Status timestamps.
- Removed the remaining Guardian-configured Vault state and zeroized secret serialization and Operator X25519 key material.

### Fixed

- Made clean Linux CI and release runners build the locked Wallet frontend before compiling the Tauri shell, removing an accidental dependency on a pre-existing local `dist` directory.
- Limited routine Dependabot version updates to reviewed minor and patch changes while keeping repository security updates enabled; breaking major upgrades remain explicit maintenance work.
- Split release validation from GitHub write credentials so tag and version parsing runs without a repository token.
- Added the accepted Linux-only Tauri/GTK advisory and unsupported native-Linux boundary to immutable release evidence and notes.

### Known limitations

- No production deployment is supported.
- Independent security audit and independent-implementation interoperability have not been completed.
- CI-Core does not provide selective disclosure, anonymous holder binding, `nym_domain`, or Verifier unlinkability; it accepts only `community` linkability.
- BBS, Digital Credentials API, Guardian Recovery, and full OpenID end-to-end interoperability are not shipped and remain planned.
- The browser Wallet is a non-secret UX preview; its Tauri shell does not yet connect the Rust Vault to every screen.
- Linux native Wallet distribution is not supported; only the macOS source target graphs and browser artifact are in the current release boundary.

[Unreleased]: https://github.com/NishizukaKoichi/commons-identity/compare/v0.1.0-preview.2...HEAD
[0.1.0-preview.2]: https://github.com/NishizukaKoichi/commons-identity/releases/tag/v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/NishizukaKoichi/commons-identity/releases/tag/v0.1.0-preview.1
