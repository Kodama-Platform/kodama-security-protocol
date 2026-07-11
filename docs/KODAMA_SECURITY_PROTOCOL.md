# Kodama Security Protocol v1

## Document Guide

This file serves two purposes:

| Part | Sections | Status |
|------|----------|--------|
| **Reference implementation** | [§2 Reference Implementation (Normative)](#2-reference-implementation-normative) | Authoritative for `@kodama/ksp-core`. Matches the TypeScript packages, test vectors, and `docs/backend-schema.sql`. |
| **Product architecture (planned)** | §3–§13 | Target Kodama Note product design. Includes features not yet in the reference library (CEK wrapping, object storage, owner sessions, etc.). |

When integrating against `@kodama/ksp-core`, follow **§2** only. See the [divergence table](#213-divergence-from-product-architecture) before reading §3+.

Related docs: [INTEGRATION.md](./INTEGRATION.md) · [AUDIT.md](./AUDIT.md) · [backend-schema.sql](./backend-schema.sql)

---

## 1. Threat Model

### 1.1 Security Goal

Kodama is a zero-knowledge, capability-based encrypted note system.

The primary security objective is:

> Kodama should never be able to read user notes, recover user passwords, or perform protected actions without valid cryptographic authorization.

Kodama separates access into three independent permission levels:

```text
Reader
↓

Can decrypt note content.
```

```text
Editor
↓

Can decrypt and update note content.
```

```text
Owner
↓

Can read, edit, rotate capabilities, delete the note, and manage the place.
```

Ownership is represented solely by the note password.

Knowing the password grants owner privileges.

The password is never transmitted to the backend.

The password is never embedded in reader or editor share links. Read-only and editor access are granted only through URLs carrying cryptographic keys in the fragment (`#...`), never the owner password.

Kodama provides no ownership transfer feature. The password is the full ownership credential for the life of the note.

---

### 1.2 Protected Assets

Kodama treats the following as **protected assets**: material that must remain under user control and must never be readable by the backend, infrastructure operators, or unauthorized third parties.

#### Client-side secrets

These are generated or derived in the browser and must never be sent to or persisted by the backend:

- **Plaintext note** — decrypted content; present in browser memory only during use
- **Owner password** — root ownership credential; never transmitted
- **Master secret** — `Argon2id(password, salt)` by default; `PBKDF2` for legacy places (see [§2.3](#23-key-derivation))
- **Read key** — HKDF-derived AES-256 key that encrypts note content (also used as the reader capability)
- **Reader capability** — base64-encoded read key; shared via URL fragment `#read=<capability>`
- **Editor private key** — Ed25519 signing seed; authorizes edits without granting ownership
- **Owner private key** — Ed25519 signing seed derived from the password; signs create payloads and owner actions
- **Compressed content blob** — gzip-compressed UTF-8 note bytes; encrypted as a blob (not plaintext strings)
- **Share links** — capability-bearing URLs (fragment keys only; never the owner password)
- **Version history (plaintext)** — prior note states; meaningful only after local decryption

#### Backend may store

Public or encrypted-at-rest metadata only:

```text
slug
product_type
kdf
ciphertext
iv
salt
version
owner_public_key
editor_public_keys
timestamps
```

#### Backend must never store

Any material that would allow decryption, impersonation, or owner actions without the user present:

```text
plaintext note
password
master secret
read key / reader capability
editor private key
owner private key
compressed note blob (in memory)
```

---

### 1.3 Trust Boundaries

Trusted:

```text
User browser
Web Crypto API
User password manager
HTTPS transport
```

Semi-trusted:

```text
Kodama backend
Database
Object storage
CDN
Backup systems
```

These systems may store encrypted content but must never have access to plaintext.

Untrusted:

```text
Internet
Readers
Editors
Network attackers
Database attackers
Malicious insiders
Compromised infrastructure
Search engines
Browser extensions
Shared computers
Injected JavaScript
```

---

### 1.4 Attacker Types

#### Passive Network Attacker

Can observe encrypted traffic.

Cannot break TLS.

Cannot decrypt note content.

---

#### Database Attacker

Obtains:

```text
ciphertext
salt
iv
editor public key
owner authentication hash
version
metadata
```

Cannot:

```text
decrypt notes
recover password
recover content key
recover reader capability
forge editor updates
perform owner actions
```

---

#### Malicious Backend

The backend is considered untrusted for confidentiality.

It may:

```text
delete data
refuse requests
return stale ciphertext
observe metadata
```

It must not be able to:

```text
decrypt notes
recover passwords
recover private keys
forge edits
perform owner actions
```

---

#### Reader

Reader possesses only the reader capability.

Reader can:

```text
decrypt notes
```

Reader cannot:

```text
edit
rotate capabilities
delete
become owner
```

---

#### Editor

Editor possesses:

```text
reader capability
editor private key
```

Editor can:

```text
decrypt
edit
submit signed updates
```

Editor cannot:

```text
delete
rotate capabilities
transfer ownership
change billing
perform admin actions
```

---

#### Owner

Owner knows the password.

The password derives owner authorization.

Owner can:

```text
read
edit
rotate capabilities
delete
change password
manage settings
```

---

#### Lost Password

If the password is lost, ownership is permanently lost.

Kodama cannot recover it.

This is a direct consequence of zero-knowledge security.

---

#### XSS

If malicious JavaScript executes inside the Kodama application,

it may access decrypted notes while open.

Mitigations include:

```text
strict CSP
Trusted Types
no third-party scripts
dependency review
separate marketing and secure origins
minimal secret lifetime
```

---

#### Malicious Browser Extensions

Browser extensions may inspect page memory.

Kodama cannot protect against compromised client devices.

---

### 1.5 Security Claims

Kodama can honestly claim:

```text
Notes are compressed and encrypted before leaving the browser.
Passwords never leave the browser.
Kodama cannot decrypt stored notes.
Readers cannot edit.
Editors cannot perform owner actions.
Database compromise alone does not reveal note content.
```

Kodama should not claim:

```text
Protection against compromised devices.
Protection against malicious browser extensions.
Password recovery.
Perfect anonymity.
Resistance to deletion or denial-of-service.
Independent cryptographic audit unless one has been completed.
```

---

## 2. Reference Implementation (Normative)

This section is the authoritative specification for `@kodama/ksp-core` v0.1.0. Types and helpers live in `packages/core/src/`.

### 2.1 Cryptographic Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Password stretching (default) | Argon2id | m=65536 KiB (64 MiB), t=3, p=1, 32-byte output |
| Password stretching (legacy) | PBKDF2-HMAC-SHA256 | 310,000 iterations, 32-byte output |
| Capability derivation | HKDF-SHA256 | Domain-separated `info` strings, no salt |
| Note compression | gzip | `CompressionStream` / `DecompressionStream` |
| Content encryption | AES-256-GCM | 12-byte random IV, optional AAD |
| Signatures | Ed25519 | 32-byte seed → key pair via `@noble/ed25519` |
| Message digests | SHA-256 | Hex-encoded in canonical messages |
| Wire encoding | Binary ciphertext + JSON metadata | Ciphertext as `Uint8Array` / `bytea` / `application/octet-stream`; base64 only for small JSON fields (keys, IV, salt, signatures) |

Random material: 32-byte salt, 12-byte IV — from `crypto.getRandomValues`.

### 2.2 Content Pipeline

Notes are **compressed before encryption**. Encryption operates on binary blobs, not UTF-8 strings.

```text
write:  UTF-8 text → gzip (Uint8Array) → encryptBytes(blob) → EncryptedBlob
wire:   metadata (JSON) + ciphertext (binary Uint8Array / multipart / octet-stream)
read:   binary ciphertext → decryptBytes → gzip decompress → UTF-8 text
sign:   canonical messages hash raw AES-GCM bytes, not base64 strings
```

Implementation:

- `compressNoteText` / `decompressNoteText` — `packages/core/src/compress.ts`
- `encryptBytes` / `decryptBytes` — return/consume `EncryptedBlob` (`Uint8Array` ciphertext + iv)
- `wire.ts` — `buildBinaryUploadFormData`, `parseBinaryUploadFormData`, split/merge helpers for metadata + binary ciphertext
- `bytesToBase64` / `base64ToBytes` — small JSON metadata only (IV, salt, keys, signatures); uses `Buffer` on Node.js

### 2.3 Key Derivation

```text
Password + Salt
  → Argon2id (default) or PBKDF2 (legacy)
    → Master Secret (32 bytes)
      → HKDF("kodama:v1:read")   → Read Key (32 bytes) — AES key + reader capability
      → HKDF("kodama:v1:editor") → Editor Seed (32 bytes) → Ed25519 key pair
      → HKDF("kodama:v1:owner")  → Owner Seed (32 bytes) → Ed25519 key pair
```

The read key encrypts note content directly. There is no separate random CEK or `wrapped_content_key` in the reference implementation.

| Field | Format | Distribution |
|-------|--------|--------------|
| Read key | Base64 32-byte AES key | `#read=<capability>` URL fragment or out-of-band |
| Editor private key | Base64 Ed25519 seed | Out-of-band only (never in URL) |
| Owner private key | Base64 Ed25519 seed | Derived from password; never shared |
| Public keys | Base64 Ed25519 public keys | Stored on backend |

Legacy places omit `kdf` on read; clients default to `pbkdf2`.

### 2.4 Additional Authenticated Data (AAD)

AAD binds ciphertext to a specific place and version:

```text
{slug}:{version}:{product_type}
```

Example: `wallet:1:note`. Must be identical on encrypt and decrypt.

### 2.5 Slug Rules

**Normalize:** trim → lowercase → whitespace to `-` → strip invalid chars → collapse `-`.

**Validate:** `^[a-z0-9-]{3,40}$`, not in reserved list (`admin`, `api`, `note`, …).

### 2.6 Canonical Messages

Newline-separated UTF-8 strings. Variable-length binary fields are represented by **SHA-256 hex digests of raw bytes**, not base64 strings.

**Create note** (signed by owner private key):

```text
kodama:v1:create-note
{slug}
{product_type}
{version}
{kdf}
sha256(raw_aes_gcm_ciphertext_bytes)
{iv_base64}
{salt_base64}
{owner_public_key_base64}
sha256(JSON.stringify(editor_public_keys))
```

**Edit note** (signed by editor private key):

```text
kodama:v1:edit-note
{slug}
{old_version}
{new_version}
sha256(raw_aes_gcm_ciphertext_bytes)
{iv_base64}
{editor_public_key_base64}
```

The `raw_aes_gcm_ciphertext_bytes` are the AES-256-GCM output over the **gzip-compressed** note blob (ciphertext includes the GCM authentication tag). API transports store the same bytes as **binary** (`bytea`, `application/octet-stream`, or a multipart `ciphertext` part)—never base64-encoded.

**Owner actions** use action-specific canonical bodies. Encrypted fields hash **raw AES-GCM bytes** (same as create/edit), not `JSON.stringify` of base64 wire fields.

`rotate-reader`:

```text
kodama:v1:owner-action
{slug}
rotate-reader
{version}
sha256(raw_aes_gcm_ciphertext_bytes)
{iv_base64}
```

`rotate-password`:

```text
kodama:v1:owner-action
{slug}
rotate-password
{version}
{kdf}
{salt_base64}
sha256(raw_aes_gcm_ciphertext_bytes)
{iv_base64}
{owner_public_key_base64}
sha256(JSON.stringify(editor_public_keys))
```

`rotate-editor`:

```text
kodama:v1:owner-action
{slug}
rotate-editor
{version}
sha256(JSON.stringify(editor_public_keys))
```

`revoke`:

```text
kodama:v1:owner-action
{slug}
revoke
{version}
{status}
{reason_or_empty}
```

Custom owner actions (no binary fields) may use `sha256(JSON.stringify(payload))` as the final line. Use `ownerActionMessageFromWire()` when verifying wire payloads.

### 2.7 Owner Signatures

Owner-only operations are authorized by **Ed25519 signatures** using the owner private key (`ownerPrivateKey`). The backend stores `owner_public_key` and verifies signatures; it never sees the private key or password.

| Operation | When signed | Key used | Wire field | Verified against |
|-----------|-------------|----------|------------|------------------|
| **Create note** | At place creation | New `ownerPrivateKey` (from password) | `owner_signature` on `CreatePlacePayload` | `owner_public_key` in the same payload |
| **Password change** | On password rotation | **Current** `ownerPrivateKey` (old password) | `signature` on `OwnerActionPayload` | Stored `owner_public_key` |
| **Admin actions** | On rotate/revoke/etc. | Current `ownerPrivateKey` | `signature` on `OwnerActionPayload` | Stored `owner_public_key` |

#### Create note

The client derives `ownerPrivateKey` from the password, builds the canonical [create message](#26-canonical-messages), signs it, and sends:

```typescript
{
  // ...ciphertext, iv, salt, kdf, keys...
  owner_public_key: string,
  owner_signature: string,  // Ed25519 over kodama:v1:create-note message
}
```

The server calls `verifyCreateNotePayload(payload)` before persisting. This proves the creator knew the password (only they could derive the matching owner key) and binds the encrypted blob to the declared public keys.

Implementation: `createNotePayload()` in `packages/core/src/protocol.ts`.

#### Password change

Changing the password replaces **all** password-derived material: master secret, read key, editor keys, and owner key. The owner must:

1. Unlock with the **current** password → derive current `ownerPrivateKey`.
2. Decrypt the note with the current read key.
3. Choose a new password → generate new salt → derive new read/editor/owner material.
4. Re-compress and re-encrypt content with the new read key.
5. Build an owner action with `action: "rotate-password"` and payload containing the new crypto fields.
6. Sign with the **current** (old) `ownerPrivateKey`.
7. Send to the server, which verifies against the **stored** `owner_public_key`.

```typescript
interface RotatePasswordPayload {
  kdf: "argon2id" | "pbkdf2";
  salt: string;                  // base64, JSON metadata
  iv: string;                    // base64, JSON metadata
  owner_public_key: string;      // from new password
  editor_public_keys: string[];
}
// ciphertext: Uint8Array — binary, sent alongside metadata (not in JSON payload)
```

```typescript
interface OwnerActionPayload<RotatePasswordPayload> {
  slug: string;
  action: "rotate-password";
  version: number;               // current place version (unchanged)
  payload: RotatePasswordPayload;
  signature: string;             // signed with OLD ownerPrivateKey
}
```

After the server accepts the action, it replaces `salt`, `kdf`, `ciphertext`, `iv`, `owner_public_key`, and `editor_public_keys`. The old password and old `ownerPrivateKey` no longer authorize anything. The client must retain the new `readerCapability`, `editorPrivateKey`, and `ownerPrivateKey` derived from the new password.

> **Implementation:** `createNotePayload()`, `createRotatePasswordAction()`, and other helpers in `packages/core/src/protocol.ts` and `packages/core/src/rotation.ts`.

#### Other owner actions

All use the same [owner-action message](#26-canonical-messages) format and `createOwnerActionPayload()`:

| `action` | Purpose |
|----------|---------|
| `rotate-reader` | Re-encrypt with a new random read key |
| `rotate-editor` | Replace authorized editor public keys |
| `rotate-password` | Replace password-derived keys and re-encrypt (spec above) |
| `revoke` | Mark place revoked or archived |

### 2.8 Wire Payloads

Field names use `snake_case`. **Encrypted blobs are never base64-encoded.** Transport uses JSON metadata plus binary ciphertext.

#### HTTP transport (recommended)

```text
POST /api/places
Content-Type: multipart/form-data

metadata   → application/json (slug, iv, salt, signatures, keys, …)
ciphertext → application/octet-stream (raw AES-GCM bytes)
```

Alternative: `application/octet-stream` body with metadata in `X-KSP-Metadata` header.

Helpers: `buildCreateUploadFormData`, `parseBinaryUploadFormData` in `packages/core/src/wire.ts`.

#### In-memory / database types

**Create place** (`CreatePlacePayload`):

```typescript
interface CreatePlacePayload {
  slug: string;
  product_type: string;       // default "note"
  version: 1;
  kdf: "argon2id" | "pbkdf2";
  iv: string;                 // base64, small JSON field
  salt: string;               // base64, small JSON field
  owner_public_key: string;
  editor_public_keys: string[];
  owner_signature: string;
  ciphertext: Uint8Array;     // binary — store as bytea, not text
}
```

**Edit place** (`EditPlacePayload`):

```typescript
interface EditPlacePayload {
  slug: string;
  old_version: number;
  new_version: number;        // must equal old_version + 1
  iv: string;
  editor_public_key: string;
  signature: string;
  ciphertext: Uint8Array;
}
```

**Owner action** (JSON metadata only for actions that re-encrypt):

```typescript
interface OwnerActionPayload<T = unknown> {
  slug: string;
  action: string;
  version: number;
  payload: T;
  signature: string;
}

interface RotateReaderPayload {
  iv: string;                 // ciphertext is binary, sent separately
}
```

#### Place bundle (multi-note / multi-tab)

A place may contain **multiple encrypted notes** (tabs) and **attachments** (binary blobs). Each item uses the same `readKey` and AAD `{slug}:{version}:{product_type}` with its own IV. The editor assigns opaque `id`s; KSP does not define tab titles or order.

**Share model:** one `readerCapability` (`base64(readKey)`) decrypts the **entire workbook** (all notes + attachments). No per-tab sharing.

**Create bundle** (`CreatePlaceBundleMetadata` + `PlaceBundle`):

```typescript
interface EncryptedItem {
  id: string;
  iv: string;
  ciphertext: Uint8Array;
}

interface PlaceBundle {
  notes: EncryptedItem[];
  attachments: EncryptedItem[];
}
```

**Wire (multipart):**

```text
metadata           → JSON (signatures, salt, note/attachment id+iv index)
note.{id}          → application/octet-stream (repeat)
attachment.{id}    → application/octet-stream (repeat)
```

Helpers: `buildCreateBundleFormData`, `parseBundleFormData`, `createPlaceBundlePayload`, `verifyCreatePlaceBundlePayload` in `@kodama/ksp-core`.

**Canonical messages:** `kodama:v1:create-place-bundle`, `kodama:v1:edit-place-bundle` — sign `bundle_digest` (SHA-256 over sorted item refs).

**Owner actions (bundle rotation):** `rotate-reader-bundle`, `rotate-password-bundle` — payload includes `bundle_digest`; re-encrypted bundle sent as multipart.

Legacy `storage_mode: legacy` single-blob places remain supported unchanged.

### 2.9 Protocol Flows

#### Create

1. Normalize and validate slug.
2. Generate salt; derive master secret (Argon2id default).
3. Derive read key, editor key, owner key.
4. `compressNoteText(plaintext)` → `encryptBytes(blob, readKey, AAD)`.
5. Sign canonical create message with **owner private key** → set `owner_signature` on metadata.
6. Upload via multipart (`metadata` + `ciphertext`); retain `readerCapability`, `editorPrivateKey`, `ownerPrivateKey` client-side.

Server: reject create if `verifyCreateNotePayload(payload)` fails.

#### Password change

1. Derive **current** `ownerPrivateKey` from current password.
2. Decrypt note with current read key.
3. Derive new material from new password + new salt.
4. Re-compress and re-encrypt with new read key.
5. Build `rotate-password` owner action; sign with **current** `ownerPrivateKey`.
6. Server verifies signature against stored `owner_public_key`, then updates crypto fields.

See [§2.7 Owner Signatures](#27-owner-signatures) for payload shapes.

#### Read (owner)

1. Fetch place record.
2. `readWithPassword(password, place)` — derives read key, decrypts, decompresses.

#### Read (reader)

1. Open URL with `#read=<base64-read-key>` (fragment not sent to server).
2. `readWithCapability(capability, place)`.

#### Edit

1. Editor holds read key + editor private key.
2. Compress new plaintext → encrypt with AAD `{slug}:{new_version}:{product_type}`.
3. Sign edit message; server verifies version, authorized editor key, signature.

#### Owner actions

| Action | Payload | Effect |
|--------|---------|--------|
| `rotate-reader` | `{ ciphertext, iv }` | Re-encrypt with new random read key; old capability invalidated |
| `rotate-editor` | `{ editor_public_keys: [...] }` | Replace authorized editor keys |
| `rotate-password` | `{ kdf, salt, ciphertext, iv, owner_public_key, editor_public_keys }` | New password; re-encrypt; new owner/editor keys |
| `revoke` | `{ status: "revoked" \| "archived", reason? }` | Mark place inactive |

Helpers: `packages/core/src/rotation.ts` (`createRotateReaderAction`, `createRotateEditorAction`, `createRotatePasswordAction`, `createRevokeAction`). Server verifiers: `@kodama/ksp-server`.

### 2.10 Backend Schema (Reference)

See [`backend-schema.sql`](./backend-schema.sql). Core columns: `slug`, `product_type`, `kdf`, `ciphertext`, `iv`, `salt`, `version`, `owner_public_key`, `editor_public_keys`.

### 2.11 Test Vectors

Deterministic interop vectors: [`test-vectors/v1.json`](../test-vectors/v1.json). Regenerate with `npm run generate-vectors -w @kodama/ksp-core`.

### 2.12 Reference API Surface

| Client | Package | Key exports |
|--------|---------|-------------|
| Browser | `@kodama/ksp-browser` | Core + `getFragmentCapability`, `buildReadOnlyUrl` |
| Server | `@kodama/ksp-server` | Verification helpers, slug validation |
| Shared | `@kodama/ksp-core` | Full crypto and protocol |

See [INTEGRATION.md](./INTEGRATION.md) for step-by-step flows.

### 2.13 Divergence from Product Architecture

| Topic | Reference implementation (§2) | Product architecture (§3+) |
|-------|--------------------------------|------------------------------|
| Content key | HKDF read key encrypts content directly | Random CEK + wrapped content key |
| Owner auth | Ed25519 owner key + signatures | Password-derived `owner_auth_hash` + sessions |
| Create proof | Owner signature over create message | Owner auth hash stored at creation |
| Compression | gzip before AES-GCM | Not specified in product sections |
| Storage | Ciphertext in DB row | Object storage + metadata DB |
| Edit message | Newline canonical string | JSON + request_id + timestamp |
| Password change | Owner action signed with old `ownerPrivateKey`; full re-encrypt | Session-based; may not re-encrypt (§9) |

---

## 3. Key Hierarchy (Product — Planned)

> **Note:** This section and §4–§13 describe the target Kodama Note product architecture. For the shipped TypeScript library, use [§2 Reference Implementation](#2-reference-implementation-normative).

### 3.1 Design Principle

Kodama separates reading, editing, and ownership into independent cryptographic capabilities.

```text
Password
        │
        ▼
   Argon2id
        │
        ▼
 Master Secret
        │
        ├────────────────┬────────────────┐
        │                │                │
        ▼                ▼                ▼
 Reader Material   Editor Material   Owner Material
        │                │                │
        ▼                ▼                ▼
 Random Content Key  Ed25519        Owner Auth
        │           Key Pair         (hash/session)
        ▼                │
 Encrypt Note            └── signs edits (does not encrypt)
```

The editor branch is **orthogonal to encryption**: the editor key pair authorizes signed updates but does not wrap or encrypt note content. §3.6 describes the editor key pair; §3.4–§3.5 describe the read/CEK path.

> **Reference implementation (`@kodama/ksp-core`):** use the diagram in [§2.3](#23-key-derivation) instead. It derives read, editor, and owner material directly from the master secret via HKDF — no random CEK, and the read key encrypts content.

---

### 3.2 Root Secret

User chooses:

```text
password
```

Browser generates:

```text
salt
```

Then derives:

```text
master_secret =
Argon2id(password, salt)
```

The password never leaves the browser.

---

### 3.3 Master Secret

The master secret exists only in browser memory.

Independent values are derived using HKDF.

```text
reader_seed =
HKDF(master_secret, "kodama:v1:reader")

editor_seed =
HKDF(master_secret, "kodama:v1:editor")

owner_seed =
HKDF(master_secret, "kodama:v1:owner")
```

These values are cryptographically independent. The editor seed becomes an Ed25519 signing key pair (§3.6); it does not participate in content encryption.

---

### 3.4 Content Encryption Key

Kodama uses a random Data Encryption Key.

```text
content_key =
random 32 bytes
```

The content key encrypts the note using:

```text
AES-256-GCM
```

A fresh IV is generated for every encryption.

```text
iv =
random 12 bytes
```

The content key never leaves the browser in plaintext.

---

### 3.5 Reader Capability

The reader capability unlocks the content key.

Example:

```text
reader_secret
```

Reader sharing:

```text
https://note.kodama.page/note#reader_secret=...
```

The browser uses the reader secret to unwrap the content key locally.

The backend never receives the reader secret.

---

### 3.6 Editor Key Pair

The browser derives an Ed25519 key pair from `editor_seed` (§3.3):

```text
editor_private_key
editor_public_key
```

The editor private key signs edits.

The backend stores only:

```text
editor_public_key
```

Edits are authorized using:

```text
Ed25519
```

---

### 3.7 Owner Authentication

Ownership is represented by the password.

The browser derives:

```text
owner_auth_secret =
HKDF(master_secret,
"kodama:v1:owner-auth")
```

Then computes:

```text
owner_auth_hash =
SHA-256(owner_auth_secret)
```

The backend stores only:

```text
owner_auth_hash
```

The backend never stores:

```text
password
master_secret
owner_auth_secret
```

Ownership is proven by knowledge of the password-derived owner authentication secret.

---

### 3.8 Capability Levels

#### Reader

Has:

```text
reader capability
```

Can:

```text
read
```

Cannot:

```text
edit
manage
```

---

#### Editor

Has:

```text
reader capability
editor private key
```

Can:

```text
read
edit
```

Cannot:

```text
manage
```

---

#### Owner

Has:

```text
password
```

The password derives:

```text
reader capability
owner authentication
```

Owner can:

```text
read
edit
rotate
delete
manage
```

---

### 3.9 Backend Storage

```text
ciphertext
iv
salt
version
editor_public_key
owner_auth_hash
crypto_suite
kdf_parameters
timestamps
```

No plaintext secrets are stored.

---

### 3.10 Why This Is Zero-Knowledge

Kodama stores only encrypted content and public verification material.

The backend never receives:

```text
password
content key
reader capability
editor private key
owner authentication secret
```

Therefore the backend cannot decrypt notes or impersonate the owner.

---

### 3.11 Key Rotation

Kodama supports:

```text
reader rotation
editor rotation
password rotation
full rotation
```

Password rotation replaces the owner authentication credentials derived from the password.

Reader rotation changes future read access.

Editor rotation changes future edit authorization.

Full rotation replaces every capability.

## 4. Create Note Protocol (Product — Planned)

### 3.1 Goal

The Create Note Protocol creates a new encrypted note without exposing plaintext, password, content key, reader capability, editor private key, or owner authentication secret to the backend.

---

### 3.2 User Inputs

The user enters:

```text
slug
password
plaintext note
```

The backend never receives:

```text
password
plaintext note
```

---

### 3.3 Browser Creation Steps

#### Step 1

Normalize slug.

---

#### Step 2

Generate:

```text
salt
```

---

#### Step 3

Derive:

```text
master_secret =
Argon2id(password, salt)
```

---

#### Step 4

Derive:

```text
reader_seed
owner_auth_secret
```

using HKDF.

---

#### Step 5

Generate:

```text
content_key
```

using secure random generation.

---

#### Step 6

Generate:

```text
reader_secret
```

Wrap the content key:

```text
wrapped_content_key =
Encrypt(
HKDF(reader_secret),
content_key
)
```

---

#### Step 7

Generate:

```text
editor_private_key
editor_public_key
```

---

#### Step 8

Compute:

```text
owner_auth_hash =
SHA-256(owner_auth_secret)
```

---

#### Step 9

Generate:

```text
iv
```

Encrypt:

```text
ciphertext =
AES-256-GCM(
content_key,
iv,
plaintext
)
```

---

### 3.4 Payload Sent to Backend

```json
{
  "slug": "wallet",
  "version": 1,
  "ciphertext": "...",
  "iv": "...",
  "salt": "...",
  "wrapped_content_key": "...",
  "editor_public_key": "...",
  "owner_auth_hash": "..."
}
```

The backend never receives:

```text
password
master_secret
content_key
reader_secret
editor_private_key
owner_auth_secret
```

---

### 3.5 Backend Validation

The backend validates:

```text
slug
version = 1
required fields
duplicate slug
crypto metadata
```

Then stores the encrypted note.

No password verification is required during creation because the backend stores only the owner authentication hash.

---

### 3.6 Backend Storage

The backend stores:

```text
slug
ciphertext
iv
salt
wrapped_content_key
editor_public_key
owner_auth_hash
version
timestamps
```

No plaintext secrets are stored.

---

### 3.7 Response

```json
{
  "ok": true,
  "slug": "wallet",
  "version": 1,
  "public_url": "https://note.kodama.page/wallet"
}
```

---

### 3.8 Security Properties

After creation:

```text
Backend cannot decrypt the note.
Backend cannot recover the password.
Backend cannot derive reader capability.
Backend cannot forge editor signatures.
Backend cannot perform owner actions without the password-derived owner authentication secret.
Database compromise reveals only encrypted data and public metadata.
```
## 5. Read Protocol (Product — Planned)

### 4.1 Goal

The Read Protocol allows a user with valid read access to decrypt note content entirely within the browser.

The backend stores only encrypted data and never participates in decryption.

---

### 4.2 Access Levels

Kodama supports three access levels.

#### Owner

Owner knows:

```text
password
```

The browser derives:

```text
master_secret
↓

reader capability
```

Owner can read every version of the note.

---

#### Editor

Editor possesses:

```text
reader capability
editor private key
```

Editor can decrypt and edit the note.

---

#### Reader

Reader possesses:

```text
reader capability
```

Reader can decrypt the note but cannot modify it.

---

### 4.3 Owner Read Flow

```text
Owner opens note URL
↓
Backend returns:

ciphertext
iv
salt
wrapped_content_key
version
crypto metadata

↓
Owner enters password

↓
Browser derives:

master_secret
↓

reader capability

↓
Browser unwraps content_key

↓

Browser decrypts ciphertext locally

↓

Plaintext appears
```

The backend never receives:

```text
password
master_secret
reader capability
content_key
plaintext
```

---

### 4.4 Reader Read Flow

Reader receives a sharing link.

Example:

```text
https://note.kodama.page/wallet#reader_secret=...
```

Flow:

```text
Reader opens URL
↓

Browser extracts reader_secret from URL fragment

↓

Backend receives only:

/wallet

↓

Backend returns:

ciphertext
wrapped_content_key
iv
version
salt

↓

Browser derives unwrap key

↓

Browser unwraps content_key

↓

Browser decrypts ciphertext

↓

Plaintext displayed
```

The backend never receives the reader secret because URL fragments are not transmitted during HTTP requests.

---

### 4.5 Browser Decryption

The browser performs:

```text
unwrap_key =
HKDF(reader_secret)

↓

content_key =
Decrypt(
wrapped_content_key
)

↓

plaintext =
AES-256-GCM-Decrypt(
content_key,
ciphertext,
iv
)
```

All cryptographic operations occur locally.

---

### 4.6 Backend Response

Endpoint:

```text
GET /api/places/:slug
```

Response:

```json
{
  "slug": "wallet",
  "version": 8,
  "ciphertext": "...",
  "wrapped_content_key": "...",
  "iv": "...",
  "salt": "...",
  "editor_public_key": "...",
  "crypto_suite": "AES-256-GCM",
  "kdf": "Argon2id"
}
```

No authentication is required to download encrypted data.

Only possession of a valid reader capability allows successful decryption.

---

### 4.7 Security Properties

The Read Protocol guarantees:

```text
Notes are decrypted only inside the browser.
The backend never receives plaintext.
The backend never receives passwords.
Readers cannot edit.
Database compromise alone cannot reveal note content.
```

---

## 6. Edit Protocol (Product — Planned)

### 5.1 Goal

The Edit Protocol allows the active editor to update encrypted content while preventing unauthorized modifications.

Kodama supports one active editor per note.

---

### 5.2 Editor Capability

Editor possesses:

```text
reader capability
editor private key
```

Editor can:

```text
decrypt
edit
encrypt
sign updates
```

Editor cannot:

```text
delete
rotate capabilities
change password
perform owner actions
```

---

### 5.3 Edit Flow

```text
Editor opens note
↓

Browser downloads encrypted note

↓

Browser unwraps content_key

↓

Browser decrypts note

↓

Editor modifies content

↓

Browser generates fresh IV

↓

Browser encrypts updated note

↓

Browser creates canonical edit message

↓

Browser signs message with editor_private_key

↓

Backend verifies signature

↓

Backend verifies version

↓

Backend stores new ciphertext

↓

Version increments
```

---

### 5.4 Canonical Edit Message

The browser signs:

```json
{
  "protocol": "kodama-note",
  "protocol_version": 1,
  "action": "edit-note",
  "slug": "wallet",
  "old_version": 8,
  "new_version": 9,
  "ciphertext_hash": "...",
  "iv": "...",
  "request_id": "uuid...",
  "timestamp": "2026-07-06T00:00:00Z"
}
```

Signature:

```text
Ed25519(editor_private_key)
```

---

### 5.5 Backend Validation

Backend accepts an edit only if:

```text
editor signature is valid
editor public key matches stored key
old_version equals current version
new_version = old_version + 1
request_id has not been used
ciphertext_hash matches uploaded ciphertext
```

If validation fails:

```text
reject update
```

---

### 5.6 Edit Request

Endpoint:

```text
POST /api/places/:slug/edit
```

Request:

```json
{
  "old_version": 8,
  "new_version": 9,
  "ciphertext": "...",
  "iv": "...",
  "ciphertext_hash": "...",
  "request_id": "uuid...",
  "signature": "..."
}
```

The backend never receives:

```text
plaintext
password
reader capability
content_key
editor private key
```

---

### 5.7 Conflict Detection

Only one version may become current.

If another edit already updated the note:

```json
{
  "ok": false,
  "error": "stale_version",
  "current_version": 9
}
```

The browser should fetch the latest encrypted version before retrying.

---

### 5.8 Security Properties

The Edit Protocol ensures:

```text
Readers cannot edit.
Backend cannot forge edits.
Replay attacks are rejected.
Version conflicts are detected.
Permission enforcement is cryptographic.
```

---

## 7. Owner/Admin Protocol (Product — Planned)

### 6.1 Goal

The Owner/Admin Protocol authorizes operations that permanently change access or cryptographic capabilities.

Ownership is represented entirely by the password.

The backend never stores or receives the password.

---

### 6.2 Owner Authentication

Ownership is represented solely by the password.

When the owner wants to perform administrative actions:

```text
Owner enters password
↓

Browser derives:

master_secret

↓

owner authentication material

↓

Browser proves ownership to the backend

↓

Backend creates a short-lived authenticated owner session

↓

Browser receives an owner session token
```

The password never leaves the browser.

The owner authentication material is used only during session creation.

After authentication succeeds, subsequent owner actions use the temporary owner session token instead of repeating the authentication process.

Recommended session lifetime:

```text
15–30 minutes of inactivity
```

The owner should be prompted for the password again after the session expires.

---

### 6.3 Owner Capabilities

Only the owner may perform:

```text
delete note
change password
rotate reader capability
rotate editor key
rotate all capabilities
change permanent settings
```

Editors and readers cannot perform these actions.

---

### 6.4 Owner Action Flow

Example: Rotate Editor Key.

```text
Owner opens Settings
↓

Owner enters password

↓

Browser derives owner authentication material

↓

Browser authenticates with backend

↓

Backend creates owner session

↓

Browser generates new editor key pair

↓

Browser builds owner action request

↓

Browser sends request using owner session token

↓

Backend validates owner session

↓

Backend performs action

↓

Owner action sequence increments
```
---

### 6.5 Owner Request

Endpoint:

```text
POST /api/places/:slug/owner-action
```

Request:

```json
{
  "owner_session_token": "...",
  "owner_action_sequence": 14,
  "action": "rotate-editor-key",
  "payload": {
    "new_editor_public_key": "..."
  },
  "request_id": "uuid..."
}
```

The backend verifies:

```text
owner session is valid
owner session has not expired
owner session belongs to this place
owner_action_sequence is correct
request_id has not been used
payload is valid
```

The session token is temporary and does not reveal the owner's password or any cryptographic keys.

If the session expires, the owner must authenticate again by entering the password.
---

### 6.6 Backend Validation

Backend accepts an owner action only if:

```text
owner authentication succeeds
owner_action_sequence is correct
request_id has not been used
action is supported
payload is valid
```

Otherwise:

```text
reject request
```

---

### 6.7 Security Properties

The Owner/Admin Protocol guarantees:

```text
Only knowledge of the password grants owner privileges.
The password is never transmitted to the backend.
The password is never included in reader or editor share links.
Editors cannot become owners.
Readers cannot become owners.
Administrative actions require successful owner authentication.
Password rotation revokes the previous password's owner privileges.
Kodama provides no ownership transfer workflow.
```
## 8. Sharing Protocol (Product — Planned)

### 7.1 Goal

Kodama uses a capability-based sharing model.

The owner's password is never shared and never appears in a share link.

Instead, the owner grants access by sharing URLs that carry cryptographic keys in the fragment (`#...`). The fragment is processed locally by the browser and is never sent to the backend.

Kodama supports three permission levels:

```text
Owner
Editor
Reader
```

Each permission level is cryptographically independent.

Sharing read access never grants edit access.

Sharing edit access never grants ownership.

Kodama provides no ownership transfer feature. There is no supported workflow to reassign ownership to another person.

---

### 7.2 Permission Model

#### Owner

Owner knows:

```text
password
```

The password derives:

```text
reader capability
owner session authentication
```

The owner can:

```text
read
edit
change password
rotate reader capability
rotate editor key
rotate all capabilities
delete note
manage settings
```

---

#### Editor

Editor possesses:

```text
reader capability
editor private key
```

The editor can:

```text
read
decrypt
edit
encrypt
sign updates
```

The editor cannot:

```text
change password
rotate capabilities
delete note
perform owner actions
```

Kodama supports only one active editor.

---

#### Reader

Reader possesses:

```text
reader capability
```

The reader can:

```text
read
decrypt
```

The reader cannot:

```text
edit
manage
delete
rotate
```

---

### 7.3 Reader Sharing

The owner creates a read-only sharing link.

The browser generates:

```text
reader_secret
```

The browser wraps the content encryption key.

```text
wrapped_content_key =
Encrypt(
    HKDF(reader_secret),
    content_key
)
```

The backend stores:

```text
wrapped_content_key
content_key_epoch
```

The browser generates:

```text
https://note.kodama.page/my-note#reader_secret=...
```

Everything after `#` remains inside the browser and is never transmitted to the backend.

When the reader opens the link:

```text
Browser extracts reader_secret
↓

Downloads ciphertext
↓

Downloads wrapped_content_key
↓

Unwraps content_key
↓

Decrypts note locally
```

The backend never receives:

```text
reader_secret
content_key
plaintext
```

---

### 7.4 Editor Sharing

The owner may grant edit access.

The browser generates:

```text
editor_private_key
editor_public_key
```

The owner establishes the new editor during an authenticated owner session.

The backend stores only:

```text
editor_public_key
```

The browser generates an editor share URL containing only capability material in the fragment, for example:

```text
https://note.kodama.page/my-note#reader_secret=...&editor_key=...
```

The editor URL never contains the owner password.

The editor receives:

```text
reader capability
editor private key
```

Both are delivered through the share URL fragment or an equivalent offline capability package — never through the password.

The editor can decrypt the note and submit signed updates.

The backend verifies every update using the stored editor public key.

---

### 7.5 Sharing Limitations

Kodama intentionally does not attempt to control information after it has been decrypted.

Once someone has successfully decrypted a note, they may:

```text
copy the text
take screenshots
print the page
save local copies
```

This is outside the scope of cryptography.

Cryptography protects access to encrypted data.

It cannot prevent users from copying plaintext after legitimate access.

---

### 7.6 Backend Knowledge

The backend stores only encrypted and public information.

The backend may know:

```text
slug
ciphertext
wrapped_content_key
version
editor_public_key
timestamps
crypto metadata
```

The backend never knows:

```text
password
reader_secret
content_key
editor_private_key
plaintext
```

---

### 7.7 Security Properties

The Sharing Protocol guarantees:

```text
Owner password is never shared.
Owner password is never embedded in reader or editor share URLs.
Reader and editor access is granted only through URLs carrying cryptographic keys.
Readers cannot edit.
Editors cannot perform owner actions.
Backend cannot decrypt shared notes.
Backend cannot create valid editor signatures.
Sharing permissions are cryptographically separated.
Kodama provides no ownership transfer workflow.
```

---

## 9. Rotation Protocol (Product — Planned)

### 8.1 Goal

Kodama does not implement revocation.

Instead, it uses rotation.

Rotation replaces cryptographic capabilities with new ones.

Future versions of the note become inaccessible using previous capabilities.

Rotation cannot erase information that has already been decrypted.

---

### 8.2 Rotation Types

Kodama supports:

```text
Reader Rotation
Editor Rotation
Password Rotation
Full Rotation
```

---

### 8.3 Reader Rotation

Reader rotation is used when:

```text
A read-only link has been shared accidentally.
A reader should no longer access future versions.
The owner wants a fresh sharing link.
```

Flow:

```text
Owner authenticates
↓

Browser decrypts current note

↓

Generate new content_key

↓

Generate new reader_secret

↓

Wrap new content_key

↓

Re-encrypt note

↓

Upload new ciphertext

↓

Increment content_key_epoch
```

Future note versions require the new reader capability.

Old reader links can no longer decrypt future ciphertext.

---

### 8.4 Editor Rotation

Editor rotation replaces the active editor.

Flow:

```text
Owner authenticates

↓

Browser generates new editor key pair

↓

Backend stores new editor_public_key

↓

Old editor key becomes invalid for future edits
```

The previous editor can no longer submit accepted updates.

Editor rotation does not automatically remove read access.

If the editor also possessed the reader capability, perform Reader Rotation as well.

---

| URL fragment | `#read=<capability>` | `#reader_secret=...` |
| HKDF labels | `kodama:v1:read`, `editor`, `owner` | `kodama:v1:reader`, `owner-auth` |

---

### 8.5 Password Rotation

> **Reference implementation:** password change uses a signed `rotate-password` owner action ([§2.7](#27-owner-signatures)), not owner auth hashes or sessions. Full re-encryption is required because the read key is password-derived.

The password is the sole ownership credential.

Changing the password replaces the owner authentication material derived from it.

Flow:

```text
Owner authenticates

↓

Owner chooses new password

↓

Browser derives new master_secret

↓

Browser derives new owner authentication material

↓

Backend updates owner authentication record

↓

Owner session is refreshed
```

The old password immediately loses owner privileges.

Password rotation does not require re-encrypting the note.

However, if password compromise is suspected, Reader Rotation and Editor Rotation should also be performed.

---

### 8.6 Full Rotation

Full Rotation replaces every active capability.

Flow:

```text
Owner authenticates

↓

Decrypt note

↓

Generate new content_key

↓

Generate new reader_secret

↓

Generate new editor key pair

↓

Generate fresh IV

↓

Re-encrypt note

↓

Wrap new content_key

↓

Upload updated ciphertext

↓

Replace editor_public_key

↓

Increment content_key_epoch
```

After Full Rotation:

```text
Old reader links cannot decrypt future versions.

Old editor keys cannot edit.

Old password no longer grants owner privileges if the password was also changed.
```

---

### 8.7 Backend Validation

Every rotation request must verify:

```text
Valid owner session

Correct owner action sequence

Unused request_id

Valid payload

Current version matches
```

If any validation fails:

```text
Reject rotation
```

---

### 8.8 Rotation Limitations

Rotation protects future access only.

Rotation cannot prevent access to information that has already been legitimately decrypted.

Rotation cannot prevent:

```text
Screenshots

Copied text

Printed copies

Compromised user devices

Malicious browser extensions

Malicious JavaScript running on the client
```

---

### 8.9 Security Properties

Rotation guarantees:

```text
Future reader access can be replaced.

Future editor authorization can be replaced.

Ownership changes immediately after password change.

Old cryptographic capabilities cannot access future protected versions.
```

---

## 10. Access Loss Limitations

### 9.1 Zero-Knowledge Model

Kodama never stores:

```text
password

master_secret

reader_secret

content_key

editor_private_key

plaintext note
```

Therefore, Kodama cannot recover these secrets.

This limitation is fundamental to zero-knowledge encryption.

---

### 9.2 Lost Password

If the owner forgets the password:

```text
Owner access is permanently lost.
```

Kodama cannot recover the password.

Kodama cannot reset the password.

Kodama cannot restore ownership.

---

### 9.3 Lost Reader Capability

If a reader loses the sharing link:

```text
Owner generates a new reader capability.

Owner shares a new link.
```

No password change is required.

---

### 9.4 Lost Editor Private Key

If the editor loses the private key:

```text
Owner performs Editor Rotation.

↓

Browser generates a new editor key pair.

↓

New editor credentials are shared.
```

The old editor key becomes invalid for future edits.

---

### 9.5 Why Kodama Cannot Recover Notes

Kodama never possesses the information required to decrypt notes.

The backend stores only encrypted content and public verification material.

Because the password and cryptographic secrets remain entirely under user control, Kodama cannot recover lost access, even as the service provider.

This limitation is the direct consequence of providing true zero-knowledge security.

---

### 9.6 User-Facing Explanation

> Your note is encrypted before it leaves your browser. Kodama never receives your password or your cryptographic secrets. Because only you possess the information required to unlock your note, Kodama cannot recover lost passwords or restore access if they are forgotten.

---

### 9.7 Investor Explanation

> Kodama implements a zero-knowledge security architecture in which ownership, editing, and reading are cryptographically separated. The service stores encrypted content and public verification data only, allowing authorization and collaboration without ever possessing the user's password or plaintext. This architecture prevents both infrastructure compromise and service operators from accessing protected content while maintaining fine-grained permission control.

---

## 11. Backend Database Schema (Product — Planned)

> **Reference implementation:** use [`backend-schema.sql`](./backend-schema.sql) instead. It stores ciphertext inline (no object storage), includes `kdf` and `owner_public_key`, and omits `wrapped_content_key`.

### 10.1 Design Principle

Kodama separates encrypted content from metadata.

Large encrypted notes are stored in object storage.

The PostgreSQL database stores only metadata, cryptographic information, routing information, and version history.

This allows Kodama to efficiently support notes larger than 10 MB while keeping database operations lightweight.

---

### 10.2 Object Storage

Encrypted note content is stored in object storage.

Example object path:

```text
notes/{place_id}/v{version}.bin
```

Object contents:

```text
ciphertext
```

The storage service never receives:

```text
plaintext
password
content key
reader capability
private keys
```

The storage service stores encrypted bytes only.

---

### 10.3 places

```sql
create table places (

    id uuid primary key default gen_random_uuid(),

    slug text not null unique,

    product_type text not null default 'note',

    current_version integer not null default 1,

    current_object_key text not null,

    current_ciphertext_sha256 text not null,

    iv text not null,

    salt text not null,

    wrapped_content_key text not null,

    editor_public_key text not null,

    owner_auth_hash text not null,

    owner_auth_salt text not null,

    content_key_epoch integer not null default 1,

    owner_action_sequence integer not null default 0,

    crypto_suite text not null,

    kdf_algorithm text not null,

    kdf_parameters jsonb not null,

    status text not null default 'active',

    created_at timestamptz not null default now(),

    updated_at timestamptz not null default now()

);
```

---

### 10.4 place_versions

```sql
create table place_versions (

    id uuid primary key default gen_random_uuid(),

    place_id uuid not null references places(id) on delete cascade,

    version integer not null,

    object_key text not null,

    ciphertext_sha256 text not null,

    iv text not null,

    content_key_epoch integer not null,

    editor_signature text not null,

    editor_request_id uuid not null,

    created_at timestamptz not null default now(),

    unique(place_id, version)

);
```

Purpose:

```text
Version history
Conflict detection
Audit trail
Rollback
```

---

### 10.5 owner_actions

```sql
create table owner_actions (

    id uuid primary key default gen_random_uuid(),

    place_id uuid not null references places(id),

    sequence integer not null,

    action text not null,

    payload jsonb not null,

    request_id uuid not null,

    created_at timestamptz not null default now(),

    unique(place_id, sequence)

);
```

Purpose:

```text
Audit owner operations
Prevent replay
Security logging
```

---

### 10.6 orders

```sql
create table orders (

    id uuid primary key default gen_random_uuid(),

    place_id uuid references places(id),

    provider text not null,

    provider_order_id text,

    amount_cents integer not null,

    currency text not null,

    status text not null,

    created_at timestamptz default now(),

    updated_at timestamptz default now()

);
```

---

### 10.7 payments

```sql
create table payments (

    id uuid primary key default gen_random_uuid(),

    order_id uuid references orders(id),

    provider text not null,

    provider_payment_id text,

    amount_cents integer not null,

    currency text not null,

    status text not null,

    raw_event jsonb,

    created_at timestamptz default now()

);
```

---

### 10.8 Backend Storage Summary

The backend stores:

```text
Encrypted object location
Ciphertext hash
IV
Salt
Wrapped content key
Editor public key
Owner authentication hash
Version metadata
Payment metadata
Audit metadata
```

The backend never stores:

```text
Plaintext note
Password
Master secret
Reader capability
Content key
Editor private key
```
## 12. API Message Format (Product — Planned)

> **Reference implementation:** wire payloads and canonical message strings are defined in [§2.6](#26-canonical-messages) and [§2.7](#27-wire-payloads). Product API below uses JSON edit messages, object storage upload, and `wrapped_content_key` — not yet implemented in `@kodama/ksp-core`.

### 11.1 Design Principles

All API requests operate on encrypted data.

The backend never processes plaintext.

Large ciphertext is uploaded directly to object storage.

The database stores metadata only.

Every edit is versioned.

---

### 11.2 Create Note

```
POST /api/places/create
```

Request:

```json
{
  "slug": "wallet",
  "product_type": "note",
  "version": 1,
  "object_key": "notes/uuid/v1.bin",
  "ciphertext_sha256": "...",
  "ciphertext_size": 12455382,
  "iv": "...",
  "salt": "...",
  "wrapped_content_key": "...",
  "editor_public_key": "...",
  "owner_auth_hash": "..."
}
```

Backend:

```text
Validates slug

Validates metadata

Registers note

Stores metadata

Object already exists in storage
```

---

### 11.3 Read Note

```
GET /api/places/:slug
```

Response:

```json
{
  "version": 8,
  "object_key": "notes/.../v8.bin",
  "ciphertext_sha256": "...",
  "ciphertext_size": 12548102,
  "iv": "...",
  "salt": "...",
  "wrapped_content_key": "...",
  "editor_public_key": "...",
  "crypto_suite": "AES-256-GCM",
  "kdf": "Argon2id"
}
```

Browser downloads ciphertext directly from object storage.

---

### 11.4 Edit Note

```
POST /api/places/:slug/edit
```

Request:

```json
{
  "old_version": 8,
  "new_version": 9,
  "object_key": "notes/.../v9.bin",
  "ciphertext_sha256": "...",
  "ciphertext_size": 12888551,
  "iv": "...",
  "request_id": "...",
  "signature": "..."
}
```

Backend validates:

```text
Editor signature

Version

Request uniqueness

Ciphertext metadata
```

Then updates metadata.

---

### 11.5 Owner Action

```
POST /api/places/:slug/owner-action
```

Request:

```json
{
  "owner_session_token": "...",
  "owner_action_sequence": 15,
  "action": "rotate-editor",
  "payload": {
    "new_editor_public_key": "..."
  },
  "request_id": "..."
}
```

Backend validates:

```text
Owner session

Sequence

Request uniqueness
```

---

### 11.6 Upload Flow

Large encrypted files should not be uploaded through the API.

Recommended flow:

```text
Browser encrypts note

↓

Request upload URL

↓

Backend returns signed upload URL

↓

Browser uploads ciphertext directly to object storage

↓

Browser calls Create/Edit API with metadata only
```

Advantages:

```text
Supports 100MB+

Supports resumable upload

Reduces backend bandwidth

Scales with CDN

No API payload limits
```

---

### 11.7 Payment API

Payment APIs remain unchanged.

Payments never receive encryption material.

Payment providers never receive plaintext note content.
## 13. Security Claims

### 13.1 Claims Kodama Can Make

Kodama can accurately claim:

1. Notes are gzip-compressed and encrypted before leaving the browser.
2. Kodama never receives user passwords.
3. Kodama never stores plaintext note content.
4. Kodama stores encrypted notes separately from metadata.
5. Readers cannot edit notes.
6. Editors cannot perform owner actions.
7. Only the password grants owner privileges.
8. The backend cannot decrypt stored notes.
9. The backend cannot forge editor updates because it does not possess the editor private key.
10. Database compromise alone does not reveal note content.
11. Object storage compromise alone does not reveal note content.
12. Payment processing is isolated from encrypted content.
13. Large notes are handled without exposing plaintext to the backend.
14. All cryptographic operations occur inside the user's browser.

---

### 13.2 Claims Kodama Must Not Make

Kodama should never claim:

1. Protection against compromised user devices.
2. Protection against malicious browser extensions.
3. Protection against malicious client-side JavaScript running in the Kodama origin.
4. Password recovery.
5. Recovery of encrypted notes without the password.
6. Perfect anonymity.
7. Resistance to censorship or deletion.
8. Prevention of copying, screenshots, or printing after decryption.
9. Independent cryptographic validation unless the protocol has been externally audited.

---

### 12.3 End-User Explanation

> Your note is encrypted inside your browser before it is uploaded. Kodama stores only encrypted data and the metadata required to retrieve it. Your password never leaves your device, and only someone with the correct password or a valid shared capability can access the note. Even if Kodama's database or storage systems are compromised, attackers cannot read your notes without the cryptographic secrets that remain under your control.

---

### 12.4 Investor Explanation

> Kodama Note implements a zero-knowledge, capability-based security architecture designed for both security and scalability. Large encrypted notes are stored in object storage, while PostgreSQL stores only metadata and public verification information. Reading, editing, and ownership are cryptographically separated, allowing the backend to authorize operations without ever possessing plaintext content, user passwords, or private signing keys. This architecture supports large encrypted documents efficiently while preserving end-to-end confidentiality.
