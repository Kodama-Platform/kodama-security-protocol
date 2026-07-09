import { bytesToUtf8, utf8ToBytes } from "./encoding.js";

/** Gzip-compress UTF-8 note text before encryption. */
export async function compressNoteText(plaintext: string): Promise<Uint8Array> {
  return compressBytes(utf8ToBytes(plaintext));
}

/** Gzip-decompress note content after decryption. */
export async function decompressNoteText(compressed: Uint8Array): Promise<string> {
  return bytesToUtf8(await decompressBytes(compressed));
}

export async function compressBytes(input: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([input as BlobPart])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function decompressBytes(compressed: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([compressed as BlobPart])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
