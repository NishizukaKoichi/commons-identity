# Commons Identity Contexts

`v1.jsonld` is the Developer Preview JSON-LD Context named by the CI-Core reference implementation:

```text
https://nishizukakoichi.github.io/commons-identity/contexts/v1.jsonld
```

CI-Core uses `eddsa-jcs-2022`; proof verification pins the exact Context URL as signed JSON data and does not fetch this resource at runtime. The hosted copy exists for vocabulary discovery and independent review. An implementation that performs semantic vocabulary checks should bundle a version-matched snapshot. A release must serve the public URL without authentication using an appropriate JSON-LD media type, publish this file's SHA-256 digest, and compare any bundled copy with it.

The `v1` URL must be immutable after a stable profile release. A semantic change requires `v2` and a new profile decision. During Developer Preview, every change must be recorded in CHANGELOG and invalidates prior interoperability claims.

Developer Preview snapshot (2026-08-03):

```text
SHA-256 dee1e1fc41aa1aef8b0b5cb012bbb7943ac935c595466283e7e5aa2cd8666b2c  v1.jsonld
```
