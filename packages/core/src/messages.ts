import { sha256Hex } from "./hash.js";
import type {
  KdfAlgorithm,
  RevokePayload,
  RotateEditorPayload,
  RotatePasswordPayload,
  RotateReaderPayload,
} from "./types.js";

export function createNoteMessage(args: {
  slug: string;
  productType: string;
  version: number;
  kdf: KdfAlgorithm;
  /** Raw AES-GCM bytes (encrypts the gzip-compressed note blob). */
  ciphertext: Uint8Array;
  iv: string;
  salt: string;
  ownerPublicKey: string;
  editorPublicKeys: string[];
}): string {
  return [
    "kodama:v1:create-note",
    args.slug,
    args.productType,
    String(args.version),
    args.kdf,
    sha256Hex(args.ciphertext),
    args.iv,
    args.salt,
    args.ownerPublicKey,
    sha256Hex(JSON.stringify(args.editorPublicKeys)),
  ].join("\n");
}

export function editNoteMessage(args: {
  slug: string;
  oldVersion: number;
  newVersion: number;
  /** Raw AES-GCM bytes (encrypts the gzip-compressed note blob). */
  ciphertext: Uint8Array;
  iv: string;
  editorPublicKey: string;
}): string {
  return [
    "kodama:v1:edit-note",
    args.slug,
    String(args.oldVersion),
    String(args.newVersion),
    sha256Hex(args.ciphertext),
    args.iv,
    args.editorPublicKey,
  ].join("\n");
}

export const OWNER_ACTION_NAMES = {
  ROTATE_READER: "rotate-reader",
  ROTATE_EDITOR: "rotate-editor",
  ROTATE_PASSWORD: "rotate-password",
  REVOKE: "revoke",
} as const;

export function rotateReaderActionMessage(args: {
  slug: string;
  version: number;
  ciphertext: Uint8Array;
  iv: string;
}): string {
  return [
    "kodama:v1:owner-action",
    args.slug,
    OWNER_ACTION_NAMES.ROTATE_READER,
    String(args.version),
    sha256Hex(args.ciphertext),
    args.iv,
  ].join("\n");
}

export function rotateEditorActionMessage(args: {
  slug: string;
  version: number;
  editorPublicKeys: string[];
}): string {
  return [
    "kodama:v1:owner-action",
    args.slug,
    OWNER_ACTION_NAMES.ROTATE_EDITOR,
    String(args.version),
    sha256Hex(JSON.stringify(args.editorPublicKeys)),
  ].join("\n");
}

export function rotatePasswordActionMessage(args: {
  slug: string;
  version: number;
  kdf: KdfAlgorithm;
  salt: string;
  ciphertext: Uint8Array;
  iv: string;
  ownerPublicKey: string;
  editorPublicKeys: string[];
}): string {
  return [
    "kodama:v1:owner-action",
    args.slug,
    OWNER_ACTION_NAMES.ROTATE_PASSWORD,
    String(args.version),
    args.kdf,
    args.salt,
    sha256Hex(args.ciphertext),
    args.iv,
    args.ownerPublicKey,
    sha256Hex(JSON.stringify(args.editorPublicKeys)),
  ].join("\n");
}

export function revokeActionMessage(args: {
  slug: string;
  version: number;
  status: RevokePayload["status"];
  reason?: string;
}): string {
  return [
    "kodama:v1:owner-action",
    args.slug,
    OWNER_ACTION_NAMES.REVOKE,
    String(args.version),
    args.status,
    args.reason ?? "",
  ].join("\n");
}

/** For custom owner actions with JSON-serializable payloads only (no binary fields). */
export function customOwnerActionMessage(args: {
  slug: string;
  action: string;
  version: number;
  payload: Record<string, unknown>;
}): string {
  return [
    "kodama:v1:owner-action",
    args.slug,
    args.action,
    String(args.version),
    sha256Hex(JSON.stringify(args.payload)),
  ].join("\n");
}

export function ownerActionMessageFromWire(args: {
  slug: string;
  action: string;
  version: number;
  payload: unknown;
  /** Raw AES-GCM bytes for actions that re-encrypt content. */
  ciphertext?: Uint8Array;
}): string {
  switch (args.action) {
    case OWNER_ACTION_NAMES.ROTATE_READER: {
      const payload = args.payload as RotateReaderPayload;
      if (!args.ciphertext) {
        throw new Error("rotate-reader requires binary ciphertext bytes");
      }
      return rotateReaderActionMessage({
        slug: args.slug,
        version: args.version,
        ciphertext: args.ciphertext,
        iv: payload.iv,
      });
    }
    case OWNER_ACTION_NAMES.ROTATE_EDITOR: {
      const payload = args.payload as RotateEditorPayload;
      return rotateEditorActionMessage({
        slug: args.slug,
        version: args.version,
        editorPublicKeys: payload.editor_public_keys,
      });
    }
    case OWNER_ACTION_NAMES.ROTATE_PASSWORD: {
      const payload = args.payload as RotatePasswordPayload;
      if (!args.ciphertext) {
        throw new Error("rotate-password requires binary ciphertext bytes");
      }
      return rotatePasswordActionMessage({
        slug: args.slug,
        version: args.version,
        kdf: payload.kdf,
        salt: payload.salt,
        ciphertext: args.ciphertext,
        iv: payload.iv,
        ownerPublicKey: payload.owner_public_key,
        editorPublicKeys: payload.editor_public_keys,
      });
    }
    case OWNER_ACTION_NAMES.REVOKE: {
      const payload = args.payload as RevokePayload;
      return revokeActionMessage({
        slug: args.slug,
        version: args.version,
        status: payload.status,
        reason: payload.reason,
      });
    }
    default:
      if (
        args.payload !== null &&
        typeof args.payload === "object" &&
        !Array.isArray(args.payload)
      ) {
        return customOwnerActionMessage({
          slug: args.slug,
          action: args.action,
          version: args.version,
          payload: args.payload as Record<string, unknown>,
        });
      }
      throw new Error(`unsupported owner action payload: ${args.action}`);
  }
}
