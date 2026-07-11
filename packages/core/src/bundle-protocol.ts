import {
  bundleDigestFromPlaceBundle,
  validatePlaceBundle,
} from "./bundle.js";
import { compressNoteText, decompressNoteText } from "./compress.js";
import { bytesToBase64, base64ToBytes } from "./encoding.js";
import { decryptBytes, encryptBytes } from "./encryption.js";
import { deriveKspMaterialFromPassword } from "./keys.js";
import {
  createPlaceBundleMessage,
  editPlaceBundleMessage,
} from "./messages.js";
import { randomSalt } from "./random.js";
import { buildContentAad, deriveReadKeyFromPassword } from "./read.js";
import { keyPairFromSeed, signMessage, verifySignature } from "./signatures.js";
import { normalizeSlug, validateSlug } from "./slug.js";
import type {
  CreatePlaceBundleMetadata,
  EditPlaceBundleMetadata,
  EncryptedItem,
  KdfAlgorithm,
  PlaceBundle,
  PlaceBundleContent,
} from "./types.js";

export interface CreatePlaceBundleInput {
  slug: string;
  password: string;
  notes: Array<{ id: string; plaintext: string }>;
  attachments?: Array<{ id: string; bytes: Uint8Array }>;
  productType?: string;
  kdf?: KdfAlgorithm;
}

export interface CreatePlaceBundleResult {
  metadata: CreatePlaceBundleMetadata;
  bundle: PlaceBundle;
  readerCapability: string;
  editorPrivateKey: string;
  ownerPrivateKey: string;
}

export interface DecryptedPlaceBundle {
  notes: Map<string, string>;
  attachments: Map<string, Uint8Array>;
}

export async function encryptNoteItem(args: {
  id: string;
  plaintext: string;
  readKey: Uint8Array;
  slug: string;
  version: number;
  productType: string;
}): Promise<EncryptedItem> {
  const aad = buildContentAad(args.slug, args.version, args.productType);
  const encrypted = await encryptBytes(
    await compressNoteText(args.plaintext),
    args.readKey,
    aad
  );
  return {
    id: args.id,
    iv: bytesToBase64(encrypted.iv),
    ciphertext: encrypted.ciphertext,
  };
}

export async function encryptAttachmentItem(args: {
  id: string;
  bytes: Uint8Array;
  readKey: Uint8Array;
  slug: string;
  version: number;
  productType: string;
}): Promise<EncryptedItem> {
  const aad = buildContentAad(args.slug, args.version, args.productType);
  const encrypted = await encryptBytes(args.bytes, args.readKey, aad);
  return {
    id: args.id,
    iv: bytesToBase64(encrypted.iv),
    ciphertext: encrypted.ciphertext,
  };
}

export async function decryptNoteItem(
  item: EncryptedItem,
  readKey: Uint8Array,
  slug: string,
  version: number,
  productType: string
): Promise<string> {
  const compressed = await decryptBytes(
    { ciphertext: item.ciphertext, iv: base64ToBytes(item.iv) },
    readKey,
    buildContentAad(slug, version, productType)
  );
  return decompressNoteText(compressed);
}

export async function decryptAttachmentItem(
  item: EncryptedItem,
  readKey: Uint8Array,
  slug: string,
  version: number,
  productType: string
): Promise<Uint8Array> {
  return decryptBytes(
    { ciphertext: item.ciphertext, iv: base64ToBytes(item.iv) },
    readKey,
    buildContentAad(slug, version, productType)
  );
}

export async function encryptPlaceBundle(args: {
  slug: string;
  version: number;
  productType: string;
  readKey: Uint8Array;
  notes: Array<{ id: string; plaintext: string }>;
  attachments: Array<{ id: string; bytes: Uint8Array }>;
}): Promise<PlaceBundle> {
  const notes: EncryptedItem[] = [];
  for (const note of args.notes) {
    notes.push(
      await encryptNoteItem({
        id: note.id,
        plaintext: note.plaintext,
        readKey: args.readKey,
        slug: args.slug,
        version: args.version,
        productType: args.productType,
      })
    );
  }

  const attachments: EncryptedItem[] = [];
  for (const attachment of args.attachments) {
    attachments.push(
      await encryptAttachmentItem({
        id: attachment.id,
        bytes: attachment.bytes,
        readKey: args.readKey,
        slug: args.slug,
        version: args.version,
        productType: args.productType,
      })
    );
  }

  return { notes, attachments };
}

export async function decryptPlaceBundle(
  readKey: Uint8Array,
  slug: string,
  version: number,
  productType: string,
  bundle: PlaceBundle
): Promise<DecryptedPlaceBundle> {
  const notes = new Map<string, string>();
  for (const note of bundle.notes) {
    notes.set(
      note.id,
      await decryptNoteItem(note, readKey, slug, version, productType)
    );
  }

  const attachments = new Map<string, Uint8Array>();
  for (const attachment of bundle.attachments) {
    attachments.set(
      attachment.id,
      await decryptAttachmentItem(
        attachment,
        readKey,
        slug,
        version,
        productType
      )
    );
  }

  return { notes, attachments };
}

export async function createPlaceBundlePayload(
  input: CreatePlaceBundleInput
): Promise<CreatePlaceBundleResult> {
  const slug = normalizeSlug(input.slug);
  const slugValidation = validateSlug(slug);
  if (!slugValidation.ok) throw new Error(slugValidation.error);

  const productType = input.productType ?? "note";
  const kdf = input.kdf ?? "argon2id";
  const version = 1 as const;
  const saltBytes = randomSalt();
  const salt = bytesToBase64(saltBytes);
  const material = await deriveKspMaterialFromPassword(
    input.password,
    saltBytes,
    kdf
  );
  const editor = await keyPairFromSeed(material.editorSeed);
  const owner = await keyPairFromSeed(material.ownerSeed);

  const bundle = await encryptPlaceBundle({
    slug,
    version,
    productType,
    readKey: material.readKey,
    notes: input.notes,
    attachments: input.attachments ?? [],
  });

  const bundleValidation = validatePlaceBundle(bundle);
  if (!bundleValidation.ok) throw new Error(bundleValidation.error);

  const digest = bundleDigestFromPlaceBundle(bundle);
  const message = createPlaceBundleMessage({
    slug,
    productType,
    version,
    kdf,
    bundleDigest: digest,
    salt,
    ownerPublicKey: owner.publicKey,
    editorPublicKeys: [editor.publicKey],
  });
  const ownerSignature = await signMessage(owner.privateKey, message);

  return {
    metadata: {
      slug,
      product_type: productType,
      version,
      kdf,
      salt,
      owner_public_key: owner.publicKey,
      editor_public_keys: [editor.publicKey],
      owner_signature: ownerSignature,
      storage_mode: "bundle",
      notes: bundle.notes.map((note) => ({ id: note.id, iv: note.iv })),
      attachments: bundle.attachments.map((attachment) => ({
        id: attachment.id,
        iv: attachment.iv,
      })),
    },
    bundle,
    readerCapability: bytesToBase64(material.readKey),
    editorPrivateKey: editor.privateKey,
    ownerPrivateKey: owner.privateKey,
  };
}

export async function verifyCreatePlaceBundlePayload(
  metadata: CreatePlaceBundleMetadata,
  bundle: PlaceBundle
): Promise<boolean> {
  const bundleValidation = validatePlaceBundle(bundle);
  if (!bundleValidation.ok) return false;

  const digest = bundleDigestFromPlaceBundle(bundle);
  const message = createPlaceBundleMessage({
    slug: metadata.slug,
    productType: metadata.product_type,
    version: metadata.version,
    kdf: metadata.kdf,
    bundleDigest: digest,
    salt: metadata.salt,
    ownerPublicKey: metadata.owner_public_key,
    editorPublicKeys: metadata.editor_public_keys,
  });
  return verifySignature(
    metadata.owner_public_key,
    message,
    metadata.owner_signature
  );
}

export async function createEditBundlePayload(args: {
  slug: string;
  oldVersion: number;
  productType: string;
  notes: Array<{ id: string; plaintext: string }>;
  attachments: Array<{ id: string; bytes: Uint8Array }>;
  readKey: Uint8Array;
  editorPrivateKey: string;
  editorPublicKey: string;
}): Promise<{ metadata: EditPlaceBundleMetadata; bundle: PlaceBundle }> {
  const newVersion = args.oldVersion + 1;
  const bundle = await encryptPlaceBundle({
    slug: args.slug,
    version: newVersion,
    productType: args.productType,
    readKey: args.readKey,
    notes: args.notes,
    attachments: args.attachments,
  });

  const bundleValidation = validatePlaceBundle(bundle);
  if (!bundleValidation.ok) throw new Error(bundleValidation.error);

  const digest = bundleDigestFromPlaceBundle(bundle);
  const message = editPlaceBundleMessage({
    slug: args.slug,
    oldVersion: args.oldVersion,
    newVersion,
    bundleDigest: digest,
    editorPublicKey: args.editorPublicKey,
  });

  return {
    metadata: {
      slug: args.slug,
      old_version: args.oldVersion,
      new_version: newVersion,
      editor_public_key: args.editorPublicKey,
      signature: await signMessage(args.editorPrivateKey, message),
      notes: bundle.notes.map((note) => ({ id: note.id, iv: note.iv })),
      attachments: bundle.attachments.map((attachment) => ({
        id: attachment.id,
        iv: attachment.iv,
      })),
      storage_mode: "bundle",
    },
    bundle,
  };
}

export async function verifyEditBundlePayload(
  metadata: EditPlaceBundleMetadata,
  bundle: PlaceBundle,
  authorizedEditorPublicKeys: string[],
  currentVersion: number
): Promise<boolean> {
  if (metadata.old_version !== currentVersion) return false;
  if (metadata.new_version !== metadata.old_version + 1) return false;
  if (!authorizedEditorPublicKeys.includes(metadata.editor_public_key)) {
    return false;
  }

  const bundleValidation = validatePlaceBundle(bundle);
  if (!bundleValidation.ok) return false;

  const digest = bundleDigestFromPlaceBundle(bundle);
  const message = editPlaceBundleMessage({
    slug: metadata.slug,
    oldVersion: metadata.old_version,
    newVersion: metadata.new_version,
    bundleDigest: digest,
    editorPublicKey: metadata.editor_public_key,
  });
  return verifySignature(
    metadata.editor_public_key,
    message,
    metadata.signature
  );
}

export async function readPlaceBundleWithPassword(
  password: string,
  place: PlaceBundleContent
): Promise<DecryptedPlaceBundle> {
  const readKey = await deriveReadKeyFromPassword(password, place);
  return readPlaceBundleWithReadKey(readKey, place);
}

export async function readPlaceBundleWithReadKey(
  readKey: Uint8Array,
  place: PlaceBundleContent
): Promise<DecryptedPlaceBundle> {
  return decryptPlaceBundle(
    readKey,
    place.slug,
    place.version,
    place.product_type,
    place.bundle
  );
}

export async function readPlaceBundleWithCapability(
  readerCapability: string,
  place: PlaceBundleContent
): Promise<DecryptedPlaceBundle> {
  return readPlaceBundleWithReadKey(base64ToBytes(readerCapability), place);
}

/** Re-encrypt an existing bundle at the same version with a new read key. */
export async function reencryptPlaceBundle(args: {
  slug: string;
  version: number;
  productType: string;
  decrypted: DecryptedPlaceBundle;
  readKey: Uint8Array;
}): Promise<PlaceBundle> {
  const notes = [...args.decrypted.notes.entries()].map(([id, plaintext]) => ({
    id,
    plaintext,
  }));
  const attachments = [...args.decrypted.attachments.entries()].map(
    ([id, bytes]) => ({ id, bytes })
  );
  return encryptPlaceBundle({
    slug: args.slug,
    version: args.version,
    productType: args.productType,
    readKey: args.readKey,
    notes,
    attachments,
  });
}
