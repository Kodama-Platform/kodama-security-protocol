# @kodama/ksp-core

Core implementation of the Kodama Security Protocol (KSP).

## Install

```bash
npm install @kodama/ksp-core
```

In this monorepo:

```bash
npm run build -w @kodama/ksp-core
npm test -w @kodama/ksp-core
npm run generate-vectors -w @kodama/ksp-core
```

## Modules

| Module | Exports |
|--------|---------|
| `kdf` | `deriveMasterSecret`, `deriveMasterSecretArgon2id`, `deriveMasterSecretPbkdf2`, `ARGON2ID_PARAMS`, `PBKDF2_ITERATIONS` |
| `keys` | `deriveKspMaterial`, `deriveKspMaterialFromPassword`, `deriveCapability` |
| `compress` | `compressNoteText`, `decompressNoteText`, `compressBytes`, `decompressBytes` |
| `encryption` | `encryptBytes`, `decryptBytes` |
| `bundle` | `bundleDigest`, `bundleDigestFromPlaceBundle`, `validatePlaceBundle` |
| `bundle-protocol` | `createPlaceBundlePayload`, `verifyCreatePlaceBundlePayload`, `createEditBundlePayload`, `verifyEditBundlePayload`, `decryptPlaceBundle`, `readPlaceBundleWithCapability` |
| `wire` | `buildBinaryUploadFormData`, `buildCreateBundleFormData`, `parseBundleFormData`, split/merge helpers |
| `read` | `readWithPassword`, `readWithCapability`, `readWithReadKey`, `buildContentAad`, `deriveReadKeyFromPassword` |
| `rotation` | `createRotateReaderAction`, `createRotateEditorAction`, `createRotatePasswordAction`, `createRevokeAction`, `OWNER_ACTIONS`, verifiers |
| `signatures` | `keyPairFromSeed`, `signMessage`, `verifySignature` |
| `messages` | `createNoteMessage`, `editNoteMessage`, action-specific owner message builders, `ownerActionMessageFromWire` |
| `protocol` | `createNotePayload`, `verifyCreateNotePayload`, `createEditPayload`, `verifyEditPayload`, owner action helpers |
| `slug` | `normalizeSlug`, `validateSlug` |
| `types` | Payload types, `KdfAlgorithm`, `PlaceContent` |

## Example

```typescript
import {
  createNotePayload,
  readWithPassword,
  verifyCreateNotePayload,
} from "@kodama/ksp-core";

const { payload, readerCapability, editorPrivateKey, ownerPrivateKey } =
  await createNotePayload({
    slug: "wallet",
    password: "user-password",
    plaintext: "secret content",
  });

const valid = await verifyCreateNotePayload(payload);
const plaintext = await readWithPassword("user-password", payload);
```

## KDF

New places use **Argon2id** by default (`kdf: "argon2id"` in the create payload). Pass `kdf: "pbkdf2"` for legacy interop only.

## Requirements

- Node.js 18+ or modern browser with `crypto.subtle` and `crypto.getRandomValues`

## Documentation

- [Protocol specification](../../docs/KODAMA_SECURITY_PROTOCOL.md)
- [Integration guide](../../docs/INTEGRATION.md)
- [Test vectors](../../test-vectors/v1.json)
