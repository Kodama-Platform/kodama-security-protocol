export type Base64 = string;

export type KdfAlgorithm = "argon2id" | "pbkdf2";

/** Raw AES-GCM output: encrypted compressed note blob + nonce. */
export interface EncryptedBlob {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

/** Stored or fetched place content. Ciphertext is binary; small fields stay in JSON metadata. */
export interface PlaceContent {
  slug: string;
  product_type: string;
  version: number;
  iv: Base64;
  salt: Base64;
  kdf?: KdfAlgorithm;
  ciphertext: Uint8Array;
}

export interface CreatePlacePayload {
  slug: string;
  product_type: string;
  version: 1;
  kdf: KdfAlgorithm;
  iv: Base64;
  salt: Base64;
  owner_public_key: Base64;
  editor_public_keys: Base64[];
  owner_signature: Base64;
  ciphertext: Uint8Array;
}

export type CreatePlaceMetadata = Omit<CreatePlacePayload, "ciphertext">;

export interface EditPlacePayload {
  slug: string;
  old_version: number;
  new_version: number;
  iv: Base64;
  editor_public_key: Base64;
  signature: Base64;
  ciphertext: Uint8Array;
}

export type EditPlaceMetadata = Omit<EditPlacePayload, "ciphertext">;

export interface OwnerActionPayload<T = unknown> {
  slug: string;
  action: string;
  version: number;
  payload: T;
  signature: Base64;
}

/** Owner action JSON metadata for rotate-reader (ciphertext is binary, sent separately). */
export interface RotateReaderPayload {
  iv: Base64;
}

/** Owner action JSON metadata for rotate-password (ciphertext is binary, sent separately). */
export interface RotatePasswordPayload {
  kdf: KdfAlgorithm;
  salt: Base64;
  iv: Base64;
  owner_public_key: Base64;
  editor_public_keys: Base64[];
}

export interface RotateEditorPayload {
  editor_public_keys: Base64[];
}

export interface RevokePayload {
  status: "revoked" | "archived";
  reason?: string;
}

/** Signed owner action plus binary ciphertext for actions that re-encrypt content. */
export interface BinaryOwnerAction<T> {
  action: OwnerActionPayload<T>;
  ciphertext: Uint8Array;
}
