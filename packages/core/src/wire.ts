import type {
  BinaryBundleOwnerAction,
  BinaryOwnerAction,
  CreatePlaceBundleMetadata,
  CreatePlaceMetadata,
  CreatePlacePayload,
  EditPlaceBundleMetadata,
  EditPlaceMetadata,
  EditPlacePayload,
  EncryptedItem,
  OwnerActionPayload,
  PlaceBundle,
  RotatePasswordBundlePayload,
  RotatePasswordPayload,
  RotateReaderBundlePayload,
  RotateReaderPayload,
} from "./types.js";

export const WIRE_PART_METADATA = "metadata";
export const WIRE_PART_CIPHERTEXT = "ciphertext";
export const WIRE_NOTE_PREFIX = "note.";
export const WIRE_ATTACHMENT_PREFIX = "attachment.";

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

function appendBundleItems(form: FormData, bundle: PlaceBundle): void {
  for (const note of bundle.notes) {
    form.append(
      `${WIRE_NOTE_PREFIX}${note.id}`,
      new Blob([note.ciphertext as BlobPart], {
        type: "application/octet-stream",
      })
    );
  }
  for (const attachment of bundle.attachments) {
    form.append(
      `${WIRE_ATTACHMENT_PREFIX}${attachment.id}`,
      new Blob([attachment.ciphertext as BlobPart], {
        type: "application/octet-stream",
      })
    );
  }
}

async function readEncryptedItemPart(
  form: FormData,
  prefix: string,
  id: string,
  iv: string
): Promise<EncryptedItem> {
  const part = form.get(`${prefix}${id}`);
  if (!(part instanceof Blob)) {
    throw new Error(`missing ${prefix}${id} part`);
  }
  return {
    id,
    iv,
    ciphertext: new Uint8Array(await part.arrayBuffer()),
  };
}

/** Build multipart/form-data for place bundle create. */
export function buildCreateBundleFormData(
  metadata: CreatePlaceBundleMetadata,
  bundle: PlaceBundle
): FormData {
  const form = new FormData();
  form.append(
    WIRE_PART_METADATA,
    new Blob([JSON.stringify(metadata)], { type: "application/json" })
  );
  appendBundleItems(form, bundle);
  return form;
}

/** Build multipart/form-data for place bundle edit. */
export function buildEditBundleFormData(
  metadata: EditPlaceBundleMetadata,
  bundle: PlaceBundle
): FormData {
  const form = new FormData();
  form.append(
    WIRE_PART_METADATA,
    new Blob([JSON.stringify(metadata)], { type: "application/json" })
  );
  appendBundleItems(form, bundle);
  return form;
}

export async function parseBundleFormData(form: FormData): Promise<{
  metadata: Record<string, unknown>;
  bundle: PlaceBundle;
}> {
  const metadataPart = form.get(WIRE_PART_METADATA);
  if (!(metadataPart instanceof Blob)) {
    throw new Error(`missing ${WIRE_PART_METADATA} part`);
  }
  const metadata = JSON.parse(await metadataPart.text()) as Record<
    string,
    unknown
  >;

  const noteRefs = extractBundleItemRefs(metadata);
  const attachmentRefs = extractBundleAttachmentRefs(metadata);

  const notes: EncryptedItem[] = [];
  for (const ref of noteRefs) {
    notes.push(
      await readEncryptedItemPart(form, WIRE_NOTE_PREFIX, ref.id, ref.iv)
    );
  }

  const attachments: EncryptedItem[] = [];
  for (const ref of attachmentRefs) {
    attachments.push(
      await readEncryptedItemPart(
        form,
        WIRE_ATTACHMENT_PREFIX,
        ref.id,
        ref.iv
      )
    );
  }

  return { metadata, bundle: { notes, attachments } };
}

function extractBundleItemRefs(
  metadata: Record<string, unknown>
): Array<{ id: string; iv: string }> {
  const refs = metadata.notes;
  return Array.isArray(refs) ? (refs as Array<{ id: string; iv: string }>) : [];
}

function extractBundleAttachmentRefs(
  metadata: Record<string, unknown>
): Array<{ id: string; iv: string }> {
  const refs = metadata.attachments;
  return Array.isArray(refs) ? (refs as Array<{ id: string; iv: string }>) : [];
}

export async function parseBundleOwnerActionFormData<T>(
  form: FormData
): Promise<{ action: OwnerActionPayload<T>; bundle: PlaceBundle }> {
  const metadataPart = form.get(WIRE_PART_METADATA);
  if (!(metadataPart instanceof Blob)) {
    throw new Error(`missing ${WIRE_PART_METADATA} part`);
  }
  const envelope = JSON.parse(await metadataPart.text()) as {
    action: OwnerActionPayload<T>;
    notes: Array<{ id: string; iv: string }>;
    attachments: Array<{ id: string; iv: string }>;
  };

  const notes: EncryptedItem[] = [];
  for (const ref of envelope.notes ?? []) {
    notes.push(
      await readEncryptedItemPart(form, WIRE_NOTE_PREFIX, ref.id, ref.iv)
    );
  }

  const attachments: EncryptedItem[] = [];
  for (const ref of envelope.attachments ?? []) {
    attachments.push(
      await readEncryptedItemPart(
        form,
        WIRE_ATTACHMENT_PREFIX,
        ref.id,
        ref.iv
      )
    );
  }

  return { action: envelope.action, bundle: { notes, attachments } };
}

export function splitBinaryBundleOwnerAction<T>(
  upload: BinaryBundleOwnerAction<T>
): { metadata: OwnerActionPayload<T>; bundle: PlaceBundle } {
  return {
    metadata: upload.action,
    bundle: upload.bundle,
  };
}

/** Build multipart/form-data for bundle owner actions (rotate reader/password). */
export function buildBundleOwnerActionFormData<T>(
  action: OwnerActionPayload<T>,
  bundle: PlaceBundle
): FormData {
  const form = new FormData();
  const envelope = {
    action,
    notes: bundle.notes.map((note) => ({ id: note.id, iv: note.iv })),
    attachments: bundle.attachments.map((attachment) => ({
      id: attachment.id,
      iv: attachment.iv,
    })),
  };
  form.append(
    WIRE_PART_METADATA,
    new Blob([JSON.stringify(envelope)], { type: "application/json" })
  );
  appendBundleItems(form, bundle);
  return form;
}

export function buildRotateReaderBundleFormData(
  upload: BinaryBundleOwnerAction<RotateReaderBundlePayload>
): FormData {
  return buildBundleOwnerActionFormData(upload.action, upload.bundle);
}

export function buildRotatePasswordBundleFormData(
  upload: BinaryBundleOwnerAction<RotatePasswordBundlePayload>
): FormData {
  return buildBundleOwnerActionFormData(upload.action, upload.bundle);
}

export function mergeCreatePlaceBundlePayload(
  metadata: CreatePlaceBundleMetadata,
  bundle: PlaceBundle
): { metadata: CreatePlaceBundleMetadata; bundle: PlaceBundle } {
  return { metadata, bundle };
}
