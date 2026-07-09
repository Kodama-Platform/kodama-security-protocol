import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, utf8ToBytes } from "./encoding.js";
export function sha256Bytes(input: Uint8Array | string): Uint8Array { return sha256(typeof input === "string" ? utf8ToBytes(input) : input); }
export function sha256Hex(input: Uint8Array | string): string { return bytesToHex(sha256Bytes(input)); }
