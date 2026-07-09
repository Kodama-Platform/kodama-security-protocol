import { sha256Hex } from "./hash.js";
import type { KdfAlgorithm } from "./types.js";

export function createNoteMessage(args: {
  slug: string;
  productType: string;
  version: number;
  kdf: KdfAlgorithm;
  ciphertext: string;
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
  ciphertext: string;
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

export function ownerActionMessage(args: {
  slug: string;
  action: string;
  version: number;
  payload: unknown;
}): string {
  return [
    "kodama:v1:owner-action",
    args.slug,
    args.action,
    String(args.version),
    sha256Hex(JSON.stringify(args.payload)),
  ].join("\n");
}
