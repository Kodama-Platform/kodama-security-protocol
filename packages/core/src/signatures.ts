import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { base64ToBytes, bytesToBase64, utf8ToBytes } from "./encoding.js";
ed.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed.etc.concatBytes(...messages));
export interface KeyPairBase64 { privateKey: string; publicKey: string; }
export async function keyPairFromSeed(seed: Uint8Array): Promise<KeyPairBase64> { if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes"); const publicKey = await ed.getPublicKeyAsync(seed); return { privateKey: bytesToBase64(seed), publicKey: bytesToBase64(publicKey) }; }
export async function signMessage(privateKeyBase64: string, message: string): Promise<string> { const signature = await ed.signAsync(utf8ToBytes(message), base64ToBytes(privateKeyBase64)); return bytesToBase64(signature); }
export async function verifySignature(publicKeyBase64: string, message: string, signatureBase64: string): Promise<boolean> { return ed.verifyAsync(base64ToBytes(signatureBase64), utf8ToBytes(message), base64ToBytes(publicKeyBase64)); }
