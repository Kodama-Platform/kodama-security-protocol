import { compressNoteText } from "./compress.js";
import { bytesToBase64 } from "./encoding.js";
import { encryptBytes } from "./encryption.js";
import { deriveKspMaterialFromPassword } from "./keys.js";
import {
  createOwnerActionPayload,
  verifyOwnerActionPayload,
} from "./protocol.js";
import { OWNER_ACTION_NAMES } from "./messages.js";
import { randomBytes, randomSalt } from "./random.js";
import { buildContentAad, readWithPassword } from "./read.js";
import { keyPairFromSeed } from "./signatures.js";
import type { KdfAlgorithm } from "./types.js";
import type {
  BinaryOwnerAction,
  OwnerActionPayload,
  PlaceContent,
  RevokePayload,
  RotateEditorPayload,
  RotatePasswordPayload,
  RotateReaderPayload,
} from "./types.js";

export const OWNER_ACTIONS = OWNER_ACTION_NAMES;

export type OwnerActionName =
  (typeof OWNER_ACTIONS)[keyof typeof OWNER_ACTIONS];

export interface RotateReaderResult extends BinaryOwnerAction<RotateReaderPayload> {
  newReaderCapability: string;
}

export interface RotatePasswordResult extends BinaryOwnerAction<RotatePasswordPayload> {
  readerCapability: string;
  editorPrivateKey: string;
  ownerPrivateKey: string;
}

/** Re-encrypt content with a new read key. Invalidates the previous reader capability. */
export async function createRotateReaderAction(args: {
  slug: string;
  version: number;
  password: string;
  place: PlaceContent;
  ownerPrivateKey: string;
}): Promise<RotateReaderResult> {
  const plaintext = await readWithPassword(args.password, args.place);
  const newReadKey = randomBytes(32);
  const encrypted = await encryptBytes(
    await compressNoteText(plaintext),
    newReadKey,
    buildContentAad(args.slug, args.version, args.place.product_type)
  );
  const actionPayload: RotateReaderPayload = {
    iv: bytesToBase64(encrypted.iv),
  };
  const action = await createOwnerActionPayload({
    slug: args.slug,
    action: OWNER_ACTIONS.ROTATE_READER,
    version: args.version,
    payload: actionPayload,
    ownerPrivateKey: args.ownerPrivateKey,
    ciphertext: encrypted.ciphertext,
  });
  return {
    action,
    ciphertext: encrypted.ciphertext,
    newReaderCapability: bytesToBase64(newReadKey),
  };
}

/** Replace password-derived keys and re-encrypt content. Signed with the current owner private key. */
export async function createRotatePasswordAction(args: {
  slug: string;
  version: number;
  currentPassword: string;
  newPassword: string;
  place: PlaceContent;
  ownerPrivateKey: string;
  kdf?: KdfAlgorithm;
}): Promise<RotatePasswordResult> {
  const plaintext = await readWithPassword(args.currentPassword, args.place);
  const kdf = args.kdf ?? "argon2id";
  const saltBytes = randomSalt();
  const salt = bytesToBase64(saltBytes);
  const material = await deriveKspMaterialFromPassword(
    args.newPassword,
    saltBytes,
    kdf
  );
  const editor = await keyPairFromSeed(material.editorSeed);
  const owner = await keyPairFromSeed(material.ownerSeed);
  const encrypted = await encryptBytes(
    await compressNoteText(plaintext),
    material.readKey,
    buildContentAad(args.slug, args.version, args.place.product_type)
  );
  const actionPayload: RotatePasswordPayload = {
    kdf,
    salt,
    iv: bytesToBase64(encrypted.iv),
    owner_public_key: owner.publicKey,
    editor_public_keys: [editor.publicKey],
  };
  const action = await createOwnerActionPayload({
    slug: args.slug,
    action: OWNER_ACTIONS.ROTATE_PASSWORD,
    version: args.version,
    payload: actionPayload,
    ownerPrivateKey: args.ownerPrivateKey,
    ciphertext: encrypted.ciphertext,
  });
  return {
    action,
    ciphertext: encrypted.ciphertext,
    readerCapability: bytesToBase64(material.readKey),
    editorPrivateKey: editor.privateKey,
    ownerPrivateKey: owner.privateKey,
  };
}

/** Replace the authorized editor public key list. */
export async function createRotateEditorAction(args: {
  slug: string;
  version: number;
  editorPublicKeys: string[];
  ownerPrivateKey: string;
}): Promise<OwnerActionPayload<RotateEditorPayload>> {
  return createOwnerActionPayload({
    slug: args.slug,
    action: OWNER_ACTIONS.ROTATE_EDITOR,
    version: args.version,
    payload: { editor_public_keys: args.editorPublicKeys },
    ownerPrivateKey: args.ownerPrivateKey,
  });
}

/** Mark a place revoked or archived. */
export async function createRevokeAction(args: {
  slug: string;
  version: number;
  status: RevokePayload["status"];
  reason?: string;
  ownerPrivateKey: string;
}): Promise<OwnerActionPayload<RevokePayload>> {
  const payload: RevokePayload = { status: args.status };
  if (args.reason !== undefined) payload.reason = args.reason;
  return createOwnerActionPayload({
    slug: args.slug,
    action: OWNER_ACTIONS.REVOKE,
    version: args.version,
    payload,
    ownerPrivateKey: args.ownerPrivateKey,
  });
}

export async function verifyRotateReaderAction(
  payload: OwnerActionPayload<RotateReaderPayload>,
  ownerPublicKey: string,
  expectedVersion: number,
  ciphertext: Uint8Array
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.ROTATE_READER) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion, {
    ciphertext,
  });
}

export async function verifyRotateEditorAction(
  payload: OwnerActionPayload<RotateEditorPayload>,
  ownerPublicKey: string,
  expectedVersion: number
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.ROTATE_EDITOR) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion);
}

export async function verifyRotatePasswordAction(
  payload: OwnerActionPayload<RotatePasswordPayload>,
  ownerPublicKey: string,
  expectedVersion: number,
  ciphertext: Uint8Array
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.ROTATE_PASSWORD) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion, {
    ciphertext,
  });
}

export async function verifyRevokeAction(
  payload: OwnerActionPayload<RevokePayload>,
  ownerPublicKey: string,
  expectedVersion: number
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.REVOKE) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion);
}
