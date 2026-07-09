export function utf8ToBytes(input: string): Uint8Array { return new TextEncoder().encode(input); }
export function bytesToUtf8(input: Uint8Array): string { return new TextDecoder().decode(input); }
export function bytesToBase64(bytes: Uint8Array): string { let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary); }
export function base64ToBytes(base64: string): Uint8Array { const binary = atob(base64); const bytes = new Uint8Array(binary.length); for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i); return bytes; }
export function bytesToHex(bytes: Uint8Array): string { return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""); }
