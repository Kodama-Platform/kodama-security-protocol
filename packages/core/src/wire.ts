import type {
  BinaryOwnerAction,
  CreatePlaceMetadata,
  CreatePlacePayload,
  EditPlaceMetadata,
  EditPlacePayload,
  OwnerActionPayload,
  RotatePasswordPayload,
  RotateReaderPayload,
} from "./types.js";

export const WIRE_PART_METADATA = "metadata";
export const WIRE_PART_CIPHERTEXT = "ciphertext";

export function splitCreatePlacePayload(payload: CreatePlacePayload): {
  metadata: CreatePlaceMetadata;
  ciphertext: Uint8Array;
} {
  const { ciphertext, ...metadata } = payload;
  return { metadata, ciphertext };
}

export function mergeCreatePlacePayload(
  metadata: CreatePlaceMetadata,
  ciphertext: Uint8Array
): CreatePlacePayload {
  return { ...metadata, ciphertext };
}

export function splitEditPlacePayload(payload: EditPlacePayload): {
  metadata: EditPlaceMetadata;
  ciphertext: Uint8Array;
} {
  const { ciphertext, ...metadata } = payload;
  return { metadata, ciphertext };
}

export function mergeEditPlacePayload(
  metadata: EditPlaceMetadata,
  ciphertext: Uint8Array
): EditPlacePayload {
  return { ...metadata, ciphertext };
}

export function splitBinaryOwnerAction<T>(
  upload: BinaryOwnerAction<T>
): { metadata: OwnerActionPayload<T>; ciphertext: Uint8Array } {
  return {
    metadata: upload.action,
    ciphertext: upload.ciphertext,
  };
}

export function mergeBinaryOwnerAction<T>(
  metadata: OwnerActionPayload<T>,
  ciphertext: Uint8Array
): BinaryOwnerAction<T> {
  return { action: metadata, ciphertext };
}

/** Build multipart/form-data for note create/edit or binary owner actions. */
export function buildBinaryUploadFormData(
  metadata: object,
  ciphertext: Uint8Array
): FormData {
  const form = new FormData();
  form.append(
    WIRE_PART_METADATA,
    new Blob([JSON.stringify(metadata)], { type: "application/json" })
  );
  form.append(
    WIRE_PART_CIPHERTEXT,
    new Blob([ciphertext as BlobPart], { type: "application/octet-stream" })
  );
  return form;
}

export async function parseBinaryUploadFormData(
  form: FormData
): Promise<{ metadata: Record<string, unknown>; ciphertext: Uint8Array }> {
  const metadataPart = form.get(WIRE_PART_METADATA);
  const ciphertextPart = form.get(WIRE_PART_CIPHERTEXT);
  if (!(metadataPart instanceof Blob)) {
    throw new Error(`missing ${WIRE_PART_METADATA} part`);
  }
  if (!(ciphertextPart instanceof Blob)) {
    throw new Error(`missing ${WIRE_PART_CIPHERTEXT} part`);
  }
  const metadata = JSON.parse(await metadataPart.text()) as Record<string, unknown>;
  const ciphertext = new Uint8Array(await ciphertextPart.arrayBuffer());
  return { metadata, ciphertext };
}

export interface OctetStreamUploadHeaders {
  "Content-Type": "application/octet-stream";
  "X-KSP-Metadata": string;
}

/** Build headers for application/octet-stream uploads with JSON metadata in a header. */
export function buildOctetStreamUploadHeaders(
  metadata: object
): OctetStreamUploadHeaders {
  return {
    "Content-Type": "application/octet-stream",
    "X-KSP-Metadata": JSON.stringify(metadata),
  };
}

export function parseOctetStreamUploadHeaders(
  headers: Headers | Record<string, string | undefined>
): Record<string, unknown> {
  const raw =
    headers instanceof Headers
      ? headers.get("X-KSP-Metadata")
      : headers["X-KSP-Metadata"];
  if (!raw) throw new Error("missing X-KSP-Metadata header");
  return JSON.parse(raw) as Record<string, unknown>;
}

export function buildCreateUploadFormData(
  payload: CreatePlacePayload
): FormData {
  const { metadata, ciphertext } = splitCreatePlacePayload(payload);
  return buildBinaryUploadFormData(metadata, ciphertext);
}

export function buildEditUploadFormData(payload: EditPlacePayload): FormData {
  const { metadata, ciphertext } = splitEditPlacePayload(payload);
  return buildBinaryUploadFormData(metadata, ciphertext);
}

export function buildRotateReaderUploadFormData(
  upload: BinaryOwnerAction<RotateReaderPayload>
): FormData {
  const { metadata, ciphertext } = splitBinaryOwnerAction(upload);
  return buildBinaryUploadFormData(metadata, ciphertext);
}

export function buildRotatePasswordUploadFormData(
  upload: BinaryOwnerAction<RotatePasswordPayload>
): FormData {
  const { metadata, ciphertext } = splitBinaryOwnerAction(upload);
  return buildBinaryUploadFormData(metadata, ciphertext);
}
