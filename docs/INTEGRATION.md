# KSP Integration Guide

This guide walks through integrating the Kodama Security Protocol into a Kodama product frontend and backend.

## Prerequisites

- Node.js 18+ (for `crypto.subtle` and Web Crypto in the reference implementation)
- `@kodama/ksp-core` on the client
- `@kodama/ksp-server` on the backend

## Package Selection

| Runtime | Package | Exports used |
|---------|---------|--------------|
| Browser / React / Next.js client | `@kodama/ksp-browser` | All of core, plus `getFragmentCapability`, `buildReadOnlyUrl` |
| Node.js / Edge API | `@kodama/ksp-server` | `verifyCreateNotePayload`, `verifyEditPayload`, `verifyOwnerActionPayload`, slug helpers |
| Shared isomorphic logic | `@kodama/ksp-core` | Full API |

## Create Flow

### Client

```typescript
import { buildCreateUploadFormData, createNotePayload } from "@kodama/ksp-core";

async function createNote(slug: string, password: string, plaintext: string) {
  const result = await createNotePayload({
    slug,
    password,
    plaintext,
    productType: "note", // optional, default "note"
  });

  const response = await fetch("/api/places", {
    method: "POST",
    body: buildCreateUploadFormData(result.payload),
  });

  if (!response.ok) throw new Error("create failed");

  // Persist locally — session storage, secure enclave, or user-managed export
  return {
    readerCapability: result.readerCapability,
    editorPrivateKey: result.editorPrivateKey,
    ownerPrivateKey: result.ownerPrivateKey,
  };
}
```

Uploads use **multipart/form-data**: `metadata` (JSON, signatures and small fields) + `ciphertext` (raw binary). Avoid JSON.stringify on encrypted blobs.

### Server

```typescript
import {
  mergeCreatePlacePayload,
  parseBinaryUploadFormData,
  verifyCreateNotePayload,
  validateSlug,
} from "@kodama/ksp-server";

async function handleCreate(request: Request) {
  const form = await request.formData();
  const { metadata, ciphertext } = await parseBinaryUploadFormData(form);
  const body = mergeCreatePlacePayload(metadata as CreatePlaceMetadata, ciphertext);

  const slugCheck = validateSlug(body.slug);
  if (!slugCheck.ok) return { status: 400, error: slugCheck.error };

  if (!(await verifyCreateNotePayload(body))) {
    return { status: 400, error: "invalid_signature" };
  }

  // INSERT into places (see backend-schema.sql) — store ciphertext as bytea
  await db.places.insert({
    slug: body.slug,
    product_type: body.product_type,
    kdf: body.kdf,
    ciphertext: body.ciphertext,
    iv: body.iv,
    salt: body.salt,
    version: body.version,
    owner_public_key: body.owner_public_key,
    editor_public_keys: body.editor_public_keys,
  });

  return { status: 201, slug: body.slug };
}
```

## Read Flow (Owner)

```typescript
import { readWithPassword } from "@kodama/ksp-core";

async function readAsOwner(
  password: string,
  place: {
    slug: string;
    product_type: string;
    version: number;
    ciphertext: Uint8Array;
    iv: string;
    salt: string;
    kdf?: "argon2id" | "pbkdf2";
  }
) {
  return readWithPassword(password, place);
}
```

The read helper derives the correct KDF from `place.kdf` (defaults to `pbkdf2` when omitted for legacy payloads) and builds AAD automatically.

## Read Flow (Reader via URL Fragment)

```typescript
import { getFragmentCapability, readWithCapability } from "@kodama/ksp-browser";

async function readFromFragment(
  place: { slug: string; product_type: string; version: number; ciphertext: Uint8Array; iv: string }
) {
  const capability = getFragmentCapability("read");
  if (!capability) throw new Error("no read capability in URL");

  return readWithCapability(capability, place);
}
```

> Ensure your router does not strip the URL hash before this code runs.

## Edit Flow

### Client

```typescript
import {
  base64ToBytes,
  buildEditUploadFormData,
  createEditPayload,
} from "@kodama/ksp-core";

async function editNote(
  place: { slug: string; version: number; product_type: string; editor_public_keys: string[] },
  secrets: { readerCapability: string; editorPrivateKey: string },
  newPlaintext: string
) {
  const editorPublicKey = place.editor_public_keys[0]!;

  const editPayload = await createEditPayload({
    slug: place.slug,
    oldVersion: place.version,
    plaintext: newPlaintext,
    readKey: base64ToBytes(secrets.readerCapability),
    editorPrivateKey: secrets.editorPrivateKey,
    editorPublicKey,
    productType: place.product_type,
  });

  const response = await fetch(`/api/places/${place.slug}/edits`, {
    method: "POST",
    body: buildEditUploadFormData(editPayload),
  });

  if (!response.ok) throw new Error("edit failed");
}
```

### Server

```typescript
import { verifyEditPayload } from "@kodama/ksp-server";

async function handleEdit(slug: string, body: EditPlacePayload) {
  const place = await db.places.findBySlug(slug);
  if (!place) return { status: 404 };

  const valid = await verifyEditPayload(
    body,
    place.editor_public_keys,
    place.version
  );

  if (!valid) return { status: 400, error: "invalid_edit" };

  // Atomic version bump
  await db.transaction(async (tx) => {
    await tx.places.update(slug, {
      ciphertext: body.ciphertext,
      iv: body.iv,
      version: body.new_version,
    });
    await tx.place_versions.insert({
      place_id: place.id,
      version: body.new_version,
      ciphertext: body.ciphertext,
      iv: body.iv,
      signed_by: body.editor_public_key,
      signature: body.signature,
    });
  });

  return { status: 200, version: body.new_version };
}
```

## Owner Action Flow

```typescript
import {
  createOwnerActionPayload,
  createRotateEditorAction,
  createRotatePasswordAction,
  createRotateReaderAction,
  createRevokeAction,
  verifyOwnerActionPayload,
} from "@kodama/ksp-core";
import {
  verifyRotateEditorAction,
  verifyRotatePasswordAction,
  verifyRotateReaderAction,
  verifyRevokeAction,
} from "@kodama/ksp-server";

// Change password (signed with current ownerPrivateKey)
const rotated = await createRotatePasswordAction({
  slug: place.slug,
  version: place.version,
  currentPassword: oldPassword,
  newPassword: newPassword,
  place,
  ownerPrivateKey: secrets.ownerPrivateKey,
});
// Server: verifyRotatePasswordAction(rotated.action, place.owner_public_key, place.version)
// Then replace salt, kdf, ciphertext, iv, owner_public_key, editor_public_keys
// Client stores rotated.readerCapability, rotated.editorPrivateKey, rotated.ownerPrivateKey

// Rotate reader capability (re-encrypts content, invalidates old capability)
const { action, newReaderCapability } = await createRotateReaderAction({
  slug: place.slug,
  version: place.version,
  password: ownerPassword,
  place,
  ownerPrivateKey: secrets.ownerPrivateKey,
});
// Server: verify with verifyRotateReaderAction(action, place.owner_public_key, place.version)
// Then update ciphertext, iv; distribute newReaderCapability to readers

// Rotate editor keys
const editorAction = await createRotateEditorAction({
  slug: place.slug,
  version: place.version,
  editorPublicKeys: [newEditorPublicKey],
  ownerPrivateKey: secrets.ownerPrivateKey,
});

// Revoke place
const revokeAction = await createRevokeAction({
  slug: place.slug,
  version: place.version,
  status: "revoked",
  reason: "compromised editor key",
  ownerPrivateKey: secrets.ownerPrivateKey,
});

// Generic owner action
const action = await createOwnerActionPayload({
  slug: "wallet",
  action: "custom-action",
  version: 2,
  payload: { key: "value" },
  ownerPrivateKey: secrets.ownerPrivateKey,
});

const ok = await verifyOwnerActionPayload(action, place.owner_public_key);
```

## Sharing Read-Only Access

```typescript
import { buildReadOnlyUrl } from "@kodama/ksp-browser";

const shareUrl = buildReadOnlyUrl(
  `https://note.kodama.app/${slug}`,
  readerCapability
);
// https://note.kodama.app/wallet#read=AbCd...
```

Never put editor or owner private keys in the URL.

## Error Handling

| Error | Cause | Client action |
|-------|-------|---------------|
| `invalid_format` / `reserved_slug` | Bad slug | Prompt user to choose another slug |
| `invalid_signature` | Tampered or wrongly signed payload | Reject; do not store |
| Decryption failure | Wrong password or wrong read capability | Prompt re-entry or deny access |
| Edit version mismatch | Concurrent edit | Refresh and retry |

## Backend Checklist

- [ ] Verify all signatures before persisting create, edit, and owner actions
- [ ] Enforce monotonic version increments on edit (optimistic concurrency)
- [ ] Never log or persist passwords, read capabilities, or private keys
- [ ] Serve place pages over HTTPS
- [ ] Do not reflect URL fragments to server-side logs (fragments are client-only)
- [ ] Store `editor_public_keys` as JSON array; validate membership on edit
- [ ] Consider rate limiting on create and edit endpoints

## Frontend Checklist

- [ ] Run slug normalization before showing availability checks
- [ ] Clear secrets from memory when the user logs out (best effort)
- [ ] Use `buildReadOnlyUrl` for share links, not manual string concatenation
- [ ] Bind decryption AAD exactly: `{slug}:{version}:{product_type}`
- [ ] Warn users that lost passwords cannot be recovered
