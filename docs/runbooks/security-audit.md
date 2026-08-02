# Runbook: Independent Security Audit

## When to use

Use this runbook before any real-person pilot, after a material cryptographic/recovery/auth change, or when commissioning an independent assessment. A dependency scanner or internal code review alone is not a third-party security audit.

## Audit outcome

The audit must answer, for an exact commit and deployment model:

- what was assessed and excluded;
- which security/privacy claims are supported or contradicted;
- how an attacker can cross each trust boundary;
- whether cryptography and protocol composition match pinned standards/profiles;
- whether the UI truthfully communicates disclosure, linkability, and unenforceable retention;
- whether findings were remediated and independently retested.

## 1. Appoint independent ownership

Name:

- project audit coordinator;
- independent assessment team and conflict statement;
- remediation owners by component;
- disclosure owner;
- final go/no-go authority for the proposed deployment.

The assessor must be free to report unfavorable findings. Commercial payment, if any, must not make the report contingent on approval.

## 2. Freeze the target

Create a read-only evidence record:

```text
Repository and commit SHA:
Protocol/profile identifiers:
Build/toolchain/lockfile digests:
Wallet/service platforms:
Deployment diagram and data residency:
Features enabled/disabled:
Test accounts and synthetic fixtures:
Known findings and accepted risks:
Assessment dates:
```

Do not audit a moving branch. Changes during assessment receive new commit IDs and explicit delta review.

## 3. Provide the evidence package

Give assessors:

- the 36-section specification and all ADRs;
- Threat Model and deployment-specific additions;
- architecture/data-flow diagrams and trust boundaries;
- CI-Core format, JCS, holder-binding, request-hash, status, recovery, and archive vectors;
- Community Profile, `CIIssuerBinding`, OperatorCredential, migration, and audit fixtures;
- build/release process, dependency locks, SBOM if available, and provenance;
- local demo instructions and all test results;
- a list of planned/experimental features not reachable in production configuration;
- previous reports, findings, waivers, incidents, and remediation evidence.

Use synthetic data. Never give assessors a real Holder Vault or production governance key.

## 4. Required review tracks

### Cryptography and key lifecycle

- CSPRNG use, key generation, domain separation, Ed25519/X25519 use;
- `eddsa-jcs-2022` transformation, proof configuration, verification method authorization, test vectors;
- holder key embedded in Credential and matching VP proof key;
- nonce/audience/expiry/replay and JCS `ciRequestHash` binding;
- key storage, zeroization limits, device revoke/rotate, Issuer/Governance compromise;
- Argon2id parameter bounds/benchmark, salt/nonce uniqueness, XChaCha20-Poly1305 AAD;
- Shamir share authenticity and Guardian ceremony, even if experimental and disabled.

### Protocol and interoperability

- VCDM 2.0 required fields and immutable bundled Context;
- custom `application/vc` and `application/vp` negotiation; no false `ldp_vc` claim;
- signed OpenID4VP Request Object, DCQL consistency, fail-closed `ci_request`;
- OID4VCI metadata discovery and signed HTTPS issuer-to-Community DID binding;
- Bitstring minimum size, separate revocation/suspension, freshness and rollback;
- `did:webvh` history, pre-rotation, predecessor/domain migration, and Commons quorum outside the DID proof;
- downgrade/unknown profile behavior and independent test implementation.

### Application and parser security

- untrusted JSON/JSON-LD/CBOR/archive/SQLite/QR/URL input;
- size, nesting, decompression, KDF allocation, timeout, SSRF, path traversal, injection;
- service authn/authz, CORS/CSRF, replay, rate limits, idempotency, error leakage;
- record encryption, filesystem permissions, backups, logs, clipboard, screenshots;
- Tauri capabilities, frontend supply chain, updater and deep-link handling;
- fuzzing and negative tests at every parser/trust boundary.

### Privacy and abuse

- cross-community keys/identifiers, rare-claim and status-index correlation;
- CI-Core's intentional rejection of `none`/`verifier-domain`;
- overbroad DCQL/claim requests and complete narrow-Credential disclosure;
- Consent Receipt sensitivity and telemetry/logging;
- malicious Issuer, Verifier, Operator, Guardian, Witness, and threshold collusion;
- coercion, account recovery abuse, discriminatory Trust Policy, continuity-link misuse;
- retention/onward-sharing as declarations, not cryptographic enforcement.

### Governance, migration, and operations

- offline Governance keys and actual quorum evidence;
- Operator scope/expiry, inability to self-renew, migration under hostile old Operator;
- mirror independence, stale/forked history, dissolution archive;
- incident detection, ownership, user notification, rollback, and key rotation drills;
- build/release provenance, maintainer access, dependency compromise, secret handling.

### Human factors and accessibility

- plain-language purpose, claim, retention, onward-sharing, and linkability display;
- no false assurance from icons, colors, “verified,” “anonymous,” or “safe” labels;
- keyboard, screen reader, reduced motion, zoom, localization, and error recovery;
- phishing-resistant display of Verifier/Community identity and high-risk operation details.

## 5. Dynamic exercises

At minimum, independently reproduce:

1. copied Credential fails holder binding;
2. replay, changed audience, expired request, changed claim, and changed transaction fail;
3. CI-Core refuses `none` and `verifier-domain`;
4. one device revokes without revoking another;
5. stale/rolled-back status becomes unknown or fails according to Policy;
6. malicious Context endpoint cannot alter JCS verification;
7. wrong/malicious `.cia` inputs fail before unsafe allocation or state mutation;
8. recovery succeeds with correct material and fails without it;
9. threshold-minus-one Guardian shares reveal no usable key and modified shares fail;
10. Operator migration survives old-Operator outage and detects state mismatch;
11. leaked Issuer key exercise identifies affected window and reissuance path;
12. independently built verifier processes the published CI-Core vectors.

## 6. Finding format

Every finding should contain:

```text
ID and severity:
Affected commit/component/profile:
Security or privacy property violated:
Prerequisites and realistic attack path:
Minimal synthetic reproduction:
Impact and affected data/people:
Recommended fix or compensating control:
Owner and target date:
Remediation commit:
Independent retest result:
Residual risk:
Disclosure status:
```

Severity must account for correlation, identity lockout, false authorization, and recovery compromise—not only code execution.

## 7. Remediation gate

- Critical/high findings are fixed and independently retested before any real-person pilot.
- Medium findings are fixed or explicitly accepted by the deployment risk owner with compensating control and expiry.
- Low/informational findings enter a public or private backlog with rationale.
- A fix that changes wire meaning uses a new profile/version and migration.
- All relevant tests and the Threat Model are updated.

The project must not edit a finding's severity or wording without assessor agreement. Project response may be published alongside it.

## 8. Publication and claims

Publish a sanitized report or executive summary that identifies the assessor, exact commit, dates, scope, exclusions, finding counts, remediation commits, retest status, and residual risks. Protect exploit details only as long as needed for coordinated remediation.

Permitted claim example:

> “Commit `<sha>` was assessed by `<assessor>` for the scope listed in `<report>`; listed critical/high findings were retested on `<sha>`.”

Do not shorten that to “Commons Identity is secure” or apply an audit to later commits, excluded components, deployment operations, or CI-Private-BBS/Guardian features outside scope.

## 9. Closeout and re-audit triggers

Archive the evidence package, report, project response, fixes, retest, risk acceptances, and next review date. Re-audit after cryptosuite/profile changes, recovery/archive format changes, authentication or update-channel changes, major parser/dependency rewrites, a severe incident, or a materially different deployment.
