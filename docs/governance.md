# Governance and Operator Separation

- Status: Initial project governance
- Effective: 2026-08-02

This document governs two different layers and keeps them separate:

1. **OSS project governance:** how this repository accepts changes and releases protocol documents and reference code.
2. **Protocol community governance:** how a deployment's Community Authority delegates operation without surrendering authority.

Maintainers of this repository are not automatically Governance Controllers, Issuers, Operators, or trust anchors for any deployed community.

## 1. Project values

Decisions must preserve:

- holder control and cross-community separation;
- no universal person identifier or global reputation score;
- no conversion of money, storage, labor volume, Credential count, or token holdings into governance power;
- reproducible evidence over authority by assertion;
- reversible, reviewable changes and public decision history;
- Authority/Operator separation and deployer choice;
- safety warnings proportionate to the project's unaudited state.

## 2. Roles

### Contributors

Anyone who reports issues, reviews designs, writes documentation or code, creates test vectors, translates material, or performs research.

### Reviewers

Contributors with demonstrated subject expertise who regularly review a bounded area. Reviewer approval is evidence, not unilateral merge authority.

### Maintainers

People entrusted with repository administration, merge, release, and security-response duties. Maintainers must disclose material conflicts of interest relevant to a decision and recuse where appropriate.

### Security responders

A minimum subset of maintainers with access to private vulnerability reports. Access is limited to people needed for triage and remediation.

The current GitHub repository permissions are the authoritative roster. A future named roster must be maintained in a reviewable file once more than one maintainer is appointed.

## 3. Change classes

| Class | Examples | Required evidence |
| --- | --- | --- |
| Editorial | typo, link, non-normative clarification | one maintainer review; no semantic change |
| Implementation | code matching an existing requirement | tests, threat impact, normal review |
| Normative compatible | new optional field/profile clarification | spec diff, vectors, ADR when judgment is material, two reviews |
| Normative breaking | identifier meaning, required field, cryptosuite, archive format | new protocol/profile version, ADR, migration, interop evidence, public review |
| Security-sensitive | key handling, parser, recovery, auth, network/file I/O | private review if needed, threat model update, independent specialist review before stable release |

No contributor may label a semantic change “editorial” to bypass review.

## 4. Decision process

1. Open an Issue or discussion describing problem, constraints, privacy impact, alternatives, and rollback.
2. For normative, medium-impact, or security-sensitive choices, add an ADR.
3. Produce the smallest reviewable change with tests or verifiable examples.
4. Allow public review appropriate to impact. Security fixes may be embargoed until coordinated disclosure.
5. Maintainers seek rough consensus grounded in evidence. Silence is not consent for breaking or security-sensitive changes.
6. If consensus cannot be reached, present no more than three concrete options with risks and migration cost. A non-recused maintainer records the decision and rationale.
7. Merge only after required gates pass. Record release-visible changes in CHANGELOG.

Appeals must identify new evidence, an unaddressed protocol principle, or a process failure. Repeating a preference without new information does not reopen a settled decision.

## 5. Protocol versions and conformance

- `commons-identity/1` meaning must not silently change after a stable release.
- Experimental extensions use distinct identifiers and cannot be required for CI-Core conformance.
- “Compatible” requires the published conformance suite for the claimed profile; self-description alone is insufficient.
- A conformance mark, certification program, or trademark policy is not established by this repository's initial release.
- Serious defects are documented; tags and history are not rewritten to hide them.

## 6. Community Authority and Operator

A deployment must treat the **Community Authority** as the source of governance and an **Operator** as a replaceable, time-bounded service provider.

### Authority retains

- governance and update keys;
- policy and schema approval;
- Issuer and Operator delegation;
- quorum records and audit checkpoint authorization;
- migration and dissolution decisions.

### Operator may receive only delegated scopes

- credential issuance hosting;
- status publication;
- encrypted registry storage;
- audit relay;
- other explicit, time-limited operational capabilities.

Infrastructure access, domain ownership, billing ownership, database administration, or employment by the Operator does not confer Community Authority.

### Minimum deployment separation

1. Governance keys are not resident on Operator application servers.
2. OperatorCredential has explicit scope and expiry, recommended at no more than 90 days.
3. Renewal requires recorded Community quorum; it is not automatic.
4. Operator cannot add itself as Authority controller.
5. Authority history, policies, Schemas, Contexts, status, and checkpoints have independent mirrors.
6. Migration export is exercised before an incident, not merely documented.
7. Old delegation is revoked only after new state is verified; old data deletion is requested and recorded without claiming impossible proof of every copy.

`did:webvh` does not enforce the Commons 3-of-5 governance rule. Deployments must enforce quorum before the authorized DID update key signs and must publish the quorum evidence hash.

## 7. Capture and conflict safeguards

- Operator funding cannot buy protocol votes or Community Authority.
- A maintainer employed by a proposed Operator discloses and recuses from a selection decision where the conflict is material.
- No single vendor-specific extension becomes Core without at least one independent implementation path.
- Telemetry, hosted trust registries, account recovery backdoors, or proprietary export requirements need a normative review and may violate the protocol principles.
- Emergency action is narrow, time-limited, logged, and followed by public retrospective when disclosure is safe.

## 8. Maintainer succession

Project maintainers should add successors based on sustained, safe contribution and review judgment, not payment or Credential count. Removal may occur for inactivity, compromised access, repeated process violation, undisclosed conflict, or Code of Conduct enforcement. Access changes must be logged through the hosting platform.

If the project becomes unmaintained, the last release remains available under its licenses. No inactive maintainer can withdraw those granted licenses. Forks may continue development but must not imply endorsement or identical conformance without passing tests.

## 9. Amending this document

Material amendments require an Issue, explicit diff, rationale, alternatives, risk/rollback note, and maintainer approval after public review. Changes may not weaken the twelve protocol principles under the same `commons-identity/1` identifier.
