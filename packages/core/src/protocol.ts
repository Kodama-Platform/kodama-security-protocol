import { compressNoteText } from "./compress.js";
import { bytesToBase64 } from "./encoding.js";
import { encryptBytes } from "./encryption.js";
import { deriveKspMaterialFromPassword } from "./keys.js";
import {
  createNoteMessage,
  editNoteMessage,
  ownerActionMessageFromWire,
} from "./messages.js";
import { randomSalt } from "./random.js";
import { buildContentAad } from "./read.js";
import { keyPairFromSeed, signMessage, verifySignature } from "./signatures.js";
import { normalizeSlug, validateSlug } from "./slug.js";
import type {
  CreatePlacePayload,
  EditPlacePayload,
  KdfAlgorithm,
  OwnerActionPayload,
} from "./types.js";

export interface CreateNoteInput {
  slug: string;
  password: string;
  plaintext: string;
  productType?: string;
  /** Defaults to argon2id. Use pbkdf2 only for legacy interop. */
  kdf?: KdfAlgorithm;
}

export interface CreateNoteResult {
  payload: CreatePlacePayload;
  readerCapability: string;
  editorPrivateKey: string;
  ownerPrivateKey: string;
}

export async function createNotePayload(
  input: CreateNoteInput
): Promise<CreateNoteResult> {
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
  const encrypted = await encryptBytes(
    await compressNoteText(input.plaintext),
    material.readKey,
    buildContentAad(slug, version, productType)
  );
  const iv = bytesToBase64(encrypted.iv);
  const message = createNoteMessage({
    slug,
    productType,
    version,
    kdf,
    ciphertext: encrypted.ciphertext,
    iv,
    salt,
    ownerPublicKey: owner.publicKey,
    editorPublicKeys: [editor.publicKey],
  });
  const ownerSignature = await signMessage(owner.privateKey, message);

  return {
    payload: {
      slug,
      product_type: productType,
      version,
      kdf,
      ciphertext: encrypted.ciphertext,
      iv,
      salt,
      owner_public_key: owner.publicKey,
      editor_public_keys: [editor.publicKey],
      owner_signature: ownerSignature,
    },
    readerCapability: bytesToBase64(material.readKey),
    editorPrivateKey: editor.privateKey,
    ownerPrivateKey: owner.privateKey,
  };
}

export async function verifyCreateNotePayload(
  payload: CreatePlacePayload
): Promise<boolean> {
  const message = createNoteMessage({
    slug: payload.slug,
    productType: payload.product_type,
    version: payload.version,
    kdf: payload.kdf,
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    salt: payload.salt,
    ownerPublicKey: payload.owner_public_key,
    editorPublicKeys: payload.editor_public_keys,
  });
  return verifySignature(
    payload.owner_public_key,
    message,
    payload.owner_signature
  );
}

export async function createEditPayload(args: {
  slug: string;
  oldVersion: number;
  plaintext: string;
  readKey: Uint8Array;
  editorPrivateKey: string;
  editorPublicKey: string;
  productType?: string;
}): Promise<EditPlacePayload> {
  const newVersion = args.oldVersion + 1;
  const productType = args.productType ?? "note";
  const encrypted = await encryptBytes(
    await compressNoteText(args.plaintext),
    args.readKey,
    buildContentAad(args.slug, newVersion, productType)
  );
  const iv = bytesToBase64(encrypted.iv);
  const message = editNoteMessage({
    slug: args.slug,
    oldVersion: args.oldVersion,
    newVersion,
    ciphertext: encrypted.ciphertext,
    iv,
    editorPublicKey: args.editorPublicKey,
  });
  return {
    slug: args.slug,
    old_version: args.oldVersion,
    new_version: newVersion,
    ciphertext: encrypted.ciphertext,
    iv,
    editor_public_key: args.editorPublicKey,
    signature: await signMessage(args.editorPrivateKey, message),
  };
}

export async function verifyEditPayload(
  payload: EditPlacePayload,
  authorizedEditorPublicKeys: string[],
  currentVersion: number
): Promise<boolean> {
  if (payload.old_version !== currentVersion) return false;
  if (payload.new_version !== payload.old_version + 1) return false;
  if (!authorizedEditorPublicKeys.includes(payload.editor_public_key))
    return false;
  const message = editNoteMessage({
    slug: payload.slug,
    oldVersion: payload.old_version,
    newVersion: payload.new_version,
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    editorPublicKey: payload.editor_public_key,
  });
  return verifySignature(
    payload.editor_public_key,
    message,
    payload.signature
  );
}

export async function createOwnerActionPayload<T>(args: {
  slug: string;
  action: string;
  version: number;
  payload: T;
  ownerPrivateKey: string;
  /** Required for rotate-reader and rotate-password. */
  ciphertext?: Uint8Array;
}): Promise<OwnerActionPayload<T>> {
  const message = ownerActionMessageFromWire({
    slug: args.slug,
    action: args.action,
    version: args.version,
    payload: args.payload,
    ciphertext: args.ciphertext,
  });
  return {
    slug: args.slug,
    action: args.action,
    version: args.version,
    payload: args.payload,
    signature: await signMessage(args.ownerPrivateKey, message),
  };
}

export async function verifyOwnerActionPayload<T>(
  payload: OwnerActionPayload<T>,
  ownerPublicKey: string,
  expectedVersion?: number,
  options?: { ciphertext?: Uint8Array }
): Promise<boolean> {
  if (expectedVersion !== undefined && payload.version !== expectedVersion) {
    return false;
  }
  const message = ownerActionMessageFromWire({
    slug: payload.slug,
    action: payload.action,
    version: payload.version,
    payload: payload.payload,
    ciphertext: options?.ciphertext,
  });
  return verifySignature(ownerPublicKey, message, payload.signature);
}
