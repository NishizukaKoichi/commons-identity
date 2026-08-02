# Commons Wallet

The reference macOS wallet shell for `commons-identity/1`, built with Tauri 2,
Vite, and vanilla TypeScript.

## Safety boundary

The browser build is an explicitly labelled interactive preview. It contains only
fictional seed data, does not generate identity keys, and never uses
`localStorage`. Passphrases entered into the Recovery screen remain in the DOM
only long enough to validate the interaction and are then cleared.

The Tauri backend currently exposes only `runtime_info`. Cryptographic vault,
credential, recovery, device-revocation, and archive-export commands are intended
to be supplied by the shared Rust Core.

## Commands

```sh
pnpm install
pnpm dev
pnpm test
pnpm lint
pnpm typecheck
pnpm build
pnpm tauri dev
```
