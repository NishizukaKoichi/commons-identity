# Security Policy

Commons Identity handles designs for identity keys, Credentials, recovery, and authorization. Treat every security report seriously—but do not treat this repository as production-safe.

> **Current assurance:** experimental, Developer Preview, unaudited. No release is approved for real-person identity, access control, employment, medical, financial, or government use.

## Supported versions

Before `1.0.0`, maintainers provide best-effort fixes only for the latest tagged pre-release and current `main`. Older commits may receive a notice but no backport. This is not a service-level commitment.

| Version | Security fixes |
| --- | --- |
| Latest pre-release | Best effort |
| `main` | Development fixes; may be unstable |
| Older versions | Not supported |

## Report a vulnerability privately

Use the repository's [private vulnerability reporting form](https://github.com/NishizukaKoichi/commons-identity/security/advisories/new). Include:

- affected commit/tag and component;
- prerequisites and realistic impact;
- minimal reproduction or test fixture using synthetic data;
- whether secrets, identity data, or third parties may be at risk;
- suggested mitigation, if known;
- your preferred name/attribution and disclosure constraints.

Do **not** put exploit details, private keys, Recovery Kits, Guardian shares, personal information, or a live target in a public Issue. If private reporting is unavailable, open a public Issue containing only “private security contact requested” and no vulnerability detail.

For Code of Conduct incidents, follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Do not mix personal safety reports into a technical vulnerability unless both are involved.

## Response targets

These are best-effort targets, not guarantees:

- acknowledge within 3 business days;
- initial triage within 7 business days;
- status update at least every 14 days while active;
- coordinate disclosure after a fix or practical mitigation exists.

Maintainers will identify a response owner, preserve the report privately, assess affected versions, and avoid requesting unnecessary personal data. A report may be closed as not applicable with a technical rationale.

## In scope

- key generation, signing, holder binding, canonicalization, and proof verification;
- Vault and SQLite record encryption;
- Recovery Kit and `.cia` Archive code; Guardian Recovery is a future design and is not shipped;
- nonce, replay, request, audience, and transaction binding;
- Status List freshness, revocation/suspension, and rollback;
- Operator delegation, migration, Authority history, and Audit Log;
- untrusted JSON/JSON-LD/CBOR/URL/QR/archive parsing and resource limits;
- service authentication/authorization, file/network I/O, and request limits;
- Wallet consent, linkability, over-disclosure, and misleading security claims;
- dependency, build, release, and update-chain compromise.

Design disagreements without an exploitable security or privacy impact belong in a public Issue. Upstream standards defects should still be reported here when the reference implementation is affected.

## Testing rules

- Test only systems and data you own or have explicit permission to assess.
- Use synthetic identities and disposable keys.
- Do not access, modify, retain, or disclose another person's data.
- Avoid denial of service, social engineering, physical attacks, and attacks on third-party infrastructure.
- Stop when you demonstrate the minimum impact needed for the report.
- Keep artifacts encrypted and delete them after coordinated resolution.

This policy does not grant permission to test deployments operated by others and is not a legal safe-harbor promise.

## Severity and disclosure

Triage considers confidentiality, integrity, availability, cross-community correlation, required privileges, user interaction, exploit reliability, affected population, and recoverability. Identity lockout and privacy correlation may be severe even without code execution.

The advisory should identify the fixed commit, affected versions, impact, mitigation, credit, and any residual risk. Release notes must not claim “audited” or “secure” merely because a reported bug was fixed. If a Credential/profile must be abandoned, maintainers will issue a new identifier rather than silently changing cryptographic meaning.

## If keys or real identity data are involved

Do not send the material itself. State the type, apparent scope, and whether it remains accessible. Maintainers will follow the narrowest response: revoke test keys, stop affected release paths, publish status/rotation guidance, and coordinate with the actual data controller. This open-source project is not automatically the controller or incident responder for an independent deployment.

See the [Threat Model](docs/threat-model.md) and [Security Audit Runbook](docs/runbooks/security-audit.md) for assurance boundaries.

## Reference service boundary

The included HTTP service deliberately starts only with `--demo`, accepts only a loopback bind/base URL, and generates ephemeral state. It is not a deployable Operator. Removing that guard without first adding durable protected keys/state, bounded enrollment proofing, operational rate limits, rollback-safe activation, and audit evidence is a security defect.

## Wallet platform boundary

The published Developer Preview artifact is the browser UX preview; it creates no keys or Vault data. The native shell is a macOS-oriented source prototype and is not released as a signed or notarized application. Linux native support is not claimed: the all-platform Tauri lock graph includes GTK3-era transitive RustSec warnings, including an unsound `glib` advisory, even though the supported macOS target graphs pass the blocking `cargo-deny` advisory policy. Resolve and re-audit that graph before distributing a Linux native binary.
