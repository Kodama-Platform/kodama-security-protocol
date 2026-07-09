import { compressNoteText } from "./compress.js";
import { bytesToBase64 } from "./encoding.js";
import { encryptBytes } from "./encryption.js";
import {
  createOwnerActionPayload,
  verifyOwnerActionPayload,
} from "./protocol.js";
import { randomBytes } from "./random.js";
import { buildContentAad, readWithPassword } from "./read.js";
import type {
  OwnerActionPayload,
  PlaceContent,
  RevokePayload,
  RotateEditorPayload,
  RotateReaderPayload,
} from "./types.js";

export const OWNER_ACTIONS = {
  ROTATE_READER: "rotate-reader",
  ROTATE_EDITOR: "rotate-editor",
  REVOKE: "revoke",
} as const;

export type OwnerActionName =
  (typeof OWNER_ACTIONS)[keyof typeof OWNER_ACTIONS];

export interface RotateReaderResult {
  action: OwnerActionPayload<RotateReaderPayload>;
  newReaderCapability: string;
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
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
  };
  const action = await createOwnerActionPayload({
    slug: args.slug,
    action: OWNER_ACTIONS.ROTATE_READER,
    version: args.version,
    payload: actionPayload,
    ownerPrivateKey: args.ownerPrivateKey,
  });
  return {
    action,
    newReaderCapability: bytesToBase64(newReadKey),
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
  expectedVersion: number
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.ROTATE_READER) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion);
}

export async function verifyRotateEditorAction(
  payload: OwnerActionPayload<RotateEditorPayload>,
  ownerPublicKey: string,
  expectedVersion: number
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.ROTATE_EDITOR) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion);
}

export async function verifyRevokeAction(
  payload: OwnerActionPayload<RevokePayload>,
  ownerPublicKey: string,
  expectedVersion: number
): Promise<boolean> {
  if (payload.action !== OWNER_ACTIONS.REVOKE) return false;
  return verifyOwnerActionPayload(payload, ownerPublicKey, expectedVersion);
}
