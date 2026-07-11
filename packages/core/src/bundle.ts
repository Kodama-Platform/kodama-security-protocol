import { sha256Hex } from "./hash.js";
import type { EncryptedItem, PlaceBundle } from "./types.js";

export const MAX_BUNDLE_NOTES = 20;
export const MAX_BUNDLE_ATTACHMENTS = 50;
export const MAX_ITEM_ID_LENGTH = 64;

export interface BundleItemRef {
  id: string;
  iv: string;
  ciphertext_sha256: string;
}

export function bundleItemRefsFromEncrypted(items: EncryptedItem[]): BundleItemRef[] {
  return items.map((item) => ({
    id: item.id,
    iv: item.iv,
    ciphertext_sha256: sha256Hex(item.ciphertext),
  }));
}

export function bundleItemRefs(bundle: PlaceBundle): {
  notes: BundleItemRef[];
  attachments: BundleItemRef[];
} {
  return {
    notes: bundleItemRefsFromEncrypted(bundle.notes),
    attachments: bundleItemRefsFromEncrypted(bundle.attachments),
  };
}

function sortRefs(refs: BundleItemRef[]): BundleItemRef[] {
  return [...refs].sort((a, b) => a.id.localeCompare(b.id));
}

/** Canonical SHA-256 hex digest over sorted note and attachment item refs. */
export function bundleDigest(
  notes: BundleItemRef[],
  attachments: BundleItemRef[]
): string {
  return sha256Hex(
    JSON.stringify({
      notes: sortRefs(notes),
      attachments: sortRefs(attachments),
    })
  );
}

export function bundleDigestFromPlaceBundle(bundle: PlaceBundle): string {
  const refs = bundleItemRefs(bundle);
  return bundleDigest(refs.notes, refs.attachments);
}

export interface BundleValidationResult {
  ok: true;
}

export interface BundleValidationError {
  ok: false;
  error: string;
}

export function validatePlaceBundle(
  bundle: PlaceBundle
): BundleValidationResult | BundleValidationError {
  if (bundle.notes.length < 1) {
    return { ok: false, error: "bundle requires at least one note" };
  }
  if (bundle.notes.length > MAX_BUNDLE_NOTES) {
    return { ok: false, error: `bundle exceeds max ${MAX_BUNDLE_NOTES} notes` };
  }
  if (bundle.attachments.length > MAX_BUNDLE_ATTACHMENTS) {
    return {
      ok: false,
      error: `bundle exceeds max ${MAX_BUNDLE_ATTACHMENTS} attachments`,
    };
  }

  const noteIds = new Set<string>();
  for (const note of bundle.notes) {
    if (!note.id || note.id.length > MAX_ITEM_ID_LENGTH) {
      return { ok: false, error: "invalid note id" };
    }
    if (noteIds.has(note.id)) {
      return { ok: false, error: `duplicate note id: ${note.id}` };
    }
    noteIds.add(note.id);
  }

  const attachmentIds = new Set<string>();
  for (const attachment of bundle.attachments) {
    if (!attachment.id || attachment.id.length > MAX_ITEM_ID_LENGTH) {
      return { ok: false, error: "invalid attachment id" };
    }
    if (attachmentIds.has(attachment.id)) {
      return { ok: false, error: `duplicate attachment id: ${attachment.id}` };
    }
    attachmentIds.add(attachment.id);
  }

  return { ok: true };
}
