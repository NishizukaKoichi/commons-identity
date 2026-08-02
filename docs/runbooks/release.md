# Runbook: Release

## When to use

Use this runbook for a maintainer-approved source, documentation, or experimental binary release. It does not authorize publishing by itself. Stop before push, tag publication, package publication, deployment, or GitHub Release unless the release owner has explicitly approved that action.

Before an independent audit and interoperability evidence exist, releases must be labeled **Developer Preview**, **experimental**, and **not for production identity infrastructure**.

## Roles

- **Release owner:** coordinates version, evidence, and final go/no-go.
- **Independent reviewer:** verifies commit, gates, license/provenance, and release notes.
- **Security reviewer:** checks open advisories, threat-model changes, and disclosure timing.
- **Publisher:** uses least-privilege credentials only after approval. Prefer a person different from the author.

One person may fill roles for an early local preview, but the release record must say so. A stable or security-sensitive release requires separation.

## 1. Define the release

Record:

```text
Version and intended tag:
Release type: docs / source / Developer Preview binary
Target commit:
Protocol/profile identifiers:
Included components/platforms:
Excluded or experimental features:
Release owner/reviewer/security reviewer:
Publication approval:
```

Never reuse a version or move a version tag. GitHub Immutable Releases must remain enabled, and the active `Immutable version tags` ruleset must reject update and deletion of `refs/tags/v*` without bypass actors. Because the standard Actions token cannot read either administrative field, the release owner must verify both in repository settings or with an administrator API token before dispatch and enter the required `PUBLICATION CONTROLS VERIFIED` confirmation. Do not store that administrator credential in Actions. Do not change the meaning of `commons-identity/1`, `ci-core-1`, a Context URL, or an archive format silently.

## 2. Freeze and inspect

Use a clean, dedicated checkout. Confirm the exact repository, branch, commit, and changes:

```sh
pwd -P
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
git status --short
git diff --check
```

The worktree must be clean for the target commit. Review every submodule or generated dependency if introduced. Confirm version consistency across Cargo workspace metadata, Wallet package, Tauri configuration, CHANGELOG, and release notes.

## 3. Documentation and standards gate

- CHANGELOG describes user-visible, breaking, privacy, and security changes.
- README and UI still say experimental/unaudited.
- Context Snapshot matches implementation.
- Normative changes have an ADR, migration, and test vectors.
- Standards maturity/dates are checked against primary immutable/final sources.
- CI-Core says `application/vc` + `application/vp`, VCDM 2.0, `eddsa-jcs-2022`, and no generic `ldp_vc` interoperability.
- The public versioned Commons Context URL resolves without authentication and its bytes match the recorded SHA-256.
- BBS, Guardian Recovery, and Digital Credentials API are not promoted into Core conformance.
- Retention and onward sharing are described as declarations.

## 4. Quality gate

From the frozen commit:

```sh
make setup
make check
make demo
git status --short
```

The final `git status --short` must be empty. The formatting stage is not allowed to change the frozen release tree silently. Save command, commit, platform, tool versions, start/end time, exit status, and artifact digests. No required gate may be waived silently. A waiver needs scope, reason, risk, owner, expiry, and prominent release-note disclosure; critical crypto/auth/recovery gates cannot be waived for a stable release.

## 5. Security, privacy, and supply-chain gate

- Review private advisories and embargo constraints.
- Update the Threat Model for changed trust boundaries, parser inputs, cryptography, recovery, auth, network/file I/O, telemetry, or dependencies.
- Inspect dependency diffs and licenses; run configured dependency/policy scans.
- Search tracked files and release artifacts for keys, tokens, Credentials, Recovery Kits, personal data, local databases, and machine-specific paths.
- Verify lockfiles are present and unchanged from the reviewed commit.
- Verify remote JSON-LD Context fetching is not introduced into CI-Core proof verification.
- Exercise malformed/archive/KDF limits for any format change.
- Confirm no test, demo, or release service points to a production endpoint.

Do not publish while a known critical/high finding affects the release unless the release is solely a coordinated security fix and the security reviewer approves the disclosure plan.

## 6. Build and provenance

Build release artifacts only from the frozen commit in a documented clean environment. Record source commit, toolchain, dependency locks, command, platform, and artifact SHA-256.

On macOS, compute a digest with:

```sh
shasum -a 256 path/to/artifact
```

Do not claim reproducible builds until a second independent environment produces matching artifacts or an explained equivalence. Signing proves key possession, not source correctness; provenance must still identify the reviewed commit.

## 7. Release notes

Release notes must include:

- Developer Preview/unaudited warning;
- exact commit and profile identifiers;
- what is implemented and what is not;
- breaking and migration notes;
- security/privacy changes and residual limits;
- gate results and audit status;
- artifact checksums and provenance link;
- upgrade and rollback instructions.

Avoid “secure,” “production-ready,” “anonymous,” “unlinkable,” “standard compliant,” or “audited” unless the scoped evidence directly supports the exact claim.

## 8. Approval and publication

The release owner and reviewer compare the candidate digest with the evidence package. After explicit approval:

1. create a signed or annotated tag pointing to the reviewed commit;
2. push the exact branch and tag once, without rewriting history;
3. record the annotated tag-object SHA and peeled commit, then recheck both against the remote ref immediately before publication;
4. create a draft GitHub Release from the approved notes;
5. upload only artifacts whose digests appear in the record and verify the complete draft asset set;
6. publish the draft so GitHub locks the Release assets and tag, then verify the Release reports `immutable`;
7. verify links, downloads, checksums, license files, warnings, and release attestation from a logged-out browser or unauthenticated client;
8. archive the release evidence.

Deployment, package-registry publication, notarization, and app-store submission are separate permissioned actions.

## 9. Post-release and rollback

Monitor vulnerability reports and download integrity. If the wrong artifact or a severe defect is published:

1. stop further distribution where reversible;
2. mark the release affected—do not erase history;
3. publish a concise advisory and safe workaround;
4. revoke compromised signing/delegation keys when applicable;
5. issue a new version/tag; never replace bytes under the old tag;
6. record root cause, affected window, remediation, and retest.

A documentation mistake may be corrected on `main`, but a released normative meaning requires an erratum or new version, not a silent rewrite.
