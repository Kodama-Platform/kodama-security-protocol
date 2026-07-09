# KSP Implementation Audit

**Date:** 2026-07-09 (updated)  
**Scope:** `kodama-security-protocol` repository, `v0.1.0`  
**Auditor:** Automated codebase review (not a substitute for independent security audit)

## Executive Summary

The repository implements KSP v1 with Argon2id password stretching (PBKDF2 retained for legacy interop), read helpers, rotation/revocation owner actions, expanded tests, and deterministic test vectors. The architecture matches the stated zero-knowledge goals.

The implementation remains **pre-production** pending independent security review.

## What Is Implemented

| Area | Status | Location |
|------|--------|----------|
| Argon2id master secret derivation (default) | Done | `packages/core/src/kdf.ts` |
| PBKDF2 master secret derivation (legacy) | Done | `packages/core/src/kdf.ts` |
| HKDF capability separation | Done | `packages/core/src/keys.ts` |
| AES-256-GCM encrypt/decrypt with AAD | Done | `packages/core/src/encryption.ts` |
| Ed25519 sign/verify | Done | `packages/core/src/signatures.ts` |
| Canonical message formats (incl. `kdf` field) | Done | `packages/core/src/messages.ts` |
| Create note payload + verification | Done | `packages/core/src/protocol.ts` |
| Edit payload + version checks | Done | `packages/core/src/protocol.ts` |
| Owner action payload + verification | Done | `packages/core/src/protocol.ts` |
| Read helpers (`readWithPassword`, `readWithCapability`) | Done | `packages/core/src/read.ts` |
| Reader/editor rotation + revocation | Done | `packages/core/src/rotation.ts` |
| Slug normalize/validate | Done | `packages/core/src/slug.ts` |
| Browser URL fragment helpers | Done | `packages/browser/src/index.ts` |
| Server verification re-exports | Done | `packages/server/src/index.ts` |
| Reference DB schema (incl. `kdf` column) | Done | `docs/backend-schema.sql` |
| Test suite (24 tests) | Done | `packages/core/test/` |
| Deterministic test vectors | Done | `test-vectors/v1.json` |

## Resolved Findings

| ID | Finding | Resolution |
|----|---------|------------|
| H1 | Argon2id vs PBKDF2 mismatch | Argon2id is the default KDF for new places; PBKDF2 available via `kdf: "pbkdf2"`. Payload includes `kdf` field bound into create signature. |
| M1 | Rotation/revocation not implemented | `createRotateReaderAction`, `createRotateEditorAction`, `createRevokeAction` + server verifiers in `rotation.ts`. |
| M2 | No read helpers | `readWithPassword`, `readWithCapability`, `buildContentAad` in `read.ts`. |
| M3 | Minimal test coverage | 24 tests across protocol, read, rotation, messages, slug, and vectors. |
| L1 | Build artifacts in `src/` | Removed; `.gitignore` updated to block future artifacts. |
| L5 | No test vectors | `test-vectors/v1.json` generated via `npm run generate-vectors -w @kodama/ksp-core`. |

## Remaining Gaps

### High Priority

| ID | Finding | Recommendation |
|----|---------|----------------|
| H2 | **No independent security review.** | Commission third-party review before production. |
| H3 | **Private keys returned as Base64 seeds.** | Document clearly; derive owner key from password on demand in apps where possible. |

### Medium Priority

| ID | Finding | Recommendation |
|----|---------|----------------|
| M4 | **No HTTP API specification.** | Add `docs/API.md` when the first product backend stabilizes. |
| M5 | **Optimistic concurrency only on edit.** | Document conflict UX; consider ETags on fetch. |

### Low Priority

| ID | Finding | Recommendation |
|----|---------|----------------|
| L2 | **Browser/server packages have no tests.** | Add smoke tests or re-use core tests via imports. |
| L3 | **`encoding.ts` uses `btoa`/`atob`.** | Document Node 18+ requirement (already in README). |
| L4 | **Single editor key at creation.** | Document multi-editor policy; use `createRotateEditorAction` to add keys. |

## Cryptographic Parameters (v1)

| Parameter | Value |
|-----------|-------|
| Default KDF | Argon2id (m=65536 KiB, t=3, p=1, 32-byte output) |
| Legacy KDF | PBKDF2-HMAC-SHA256 (310,000 iterations) |
| Content encryption | AES-256-GCM, 12-byte IV |
| Signatures | Ed25519 |
| AAD | `{slug}:{version}:{product_type}` |

## Dependency Surface

| Package | Version | Role |
|---------|---------|------|
| `hash-wasm` | ^4.12.0 | Argon2id (WASM) |
| `@noble/ed25519` | ^2.1.0 | Signatures |
| `@noble/hashes` | ^1.4.0 | SHA-256, SHA-512, HKDF |
| Web Crypto (`crypto.subtle`) | Platform | PBKDF2, AES-GCM |

## Recommended Next Steps

1. Schedule independent security audit before production.
2. Add HTTP API specification when backend routes stabilize.
3. Add browser/server package smoke tests.
