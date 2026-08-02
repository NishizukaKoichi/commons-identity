# License Map

Commons Identity uses separate licenses for software and prose.

| Material | License | Location |
| --- | --- | --- |
| Rust/TypeScript/CSS/HTML source, tests, build/config files, scripts | Apache-2.0 | [`../LICENSE`](../LICENSE) |
| Machine-readable Contexts, Schemas, fixtures, protocol examples intended for implementation | Apache-2.0 | [`../LICENSE`](../LICENSE) |
| `docs/`, `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, prose portions of examples | CC BY 4.0 | [`CC-BY-4.0.md`](CC-BY-4.0.md) |
| Third-party dependencies or adapted material | Upstream license | Dependency metadata and applicable notice |

Where a prose document contains a code block that is independently reusable as software or a machine-readable protocol example, that code block may also be used under Apache-2.0. This additional permission does not change the CC BY 4.0 license of the surrounding prose.

## Attribution for documentation

A reasonable attribution is:

> “Commons Identity Protocol documentation,” Commons Identity contributors, licensed under CC BY 4.0, source: https://github.com/NishizukaKoichi/commons-identity. Modified by `<name>` on `<date>`.

Retain the creator/project name, license link, source link, and an indication of changes. CC BY 4.0 does not grant trademark rights or endorsement.

## Contributions

Unless explicitly marked otherwise, intentional contributions are provided under the license mapped to the destination file. Contributors must have the right to provide their work and must preserve required third-party attribution.

SPDX identifiers may be used in files:

```text
SPDX-License-Identifier: Apache-2.0
SPDX-License-Identifier: CC-BY-4.0
```

If a new artifact does not fit this map, resolve it in an ADR before release rather than guessing.
