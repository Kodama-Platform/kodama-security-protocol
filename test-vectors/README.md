# Test Vectors

Deterministic interoperability test vectors for KSP v1.

## Files

| File | Description |
|------|-------------|
| `v1.json` | Fixed salt/IV Argon2id and PBKDF2 derivations, encryption, create-note signature, slug cases |

## Regenerating

```bash
npm run generate-vectors -w @kodama/ksp-core
```

This uses fixed salt (`0x42…`) and IV (`0x11…`) via the test-only `setRandomOverride` hook in `@kodama/ksp-core`.

## Cross-Language Interop

Third-party implementations should verify against `v1.json`:

1. **Argon2id** — password `correct horse battery staple`, salt `4242…42`, params m=65536 KiB, t=3, p=1
2. **PBKDF2** — same password/salt, 310,000 iterations, SHA-256
3. **HKDF** — info strings `kodama:v1:read`, `kodama:v1:editor`, `kodama:v1:owner`
4. **Gzip compression** — UTF-8 note text compressed before encryption (`compression.compressed_hex` in vectors)
5. **AES-256-GCM** — AAD `wallet:1:note`, fixed IV; encrypts compressed blob; canonical messages hash **raw ciphertext bytes** (`encryption.ciphertext_hex`)
6. **Create message** — canonical string in `create_note.canonical_message`, signed by owner key

Automated verification runs in `packages/core/test/vectors.test.ts`.
