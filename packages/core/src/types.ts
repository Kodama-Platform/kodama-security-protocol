export type Base64 = string;

export type KdfAlgorithm = "argon2id" | "pbkdf2";

export interface EncryptedPayload {
  ciphertext: Base64;
  iv: Base64;
}

export interface PlaceContent {
  slug: string;
  product_type: string;
  version: number;
  ciphertext: Base64;
  iv: Base64;
  salt: Base64;
  kdf?: KdfAlgorithm;
}

export interface CreatePlacePayload {
  slug: string;
  product_type: string;
  version: 1;
  kdf: KdfAlgorithm;
  ciphertext: Base64;
  iv: Base64;
  salt: Base64;
  owner_public_key: Base64;
  editor_public_keys: Base64[];
  owner_signature: Base64;
}

export interface EditPlacePayload {
  slug: string;
  old_version: number;
  new_version: number;
  ciphertext: Base64;
  iv: Base64;
  editor_public_key: Base64;
  signature: Base64;
}

export interface OwnerActionPayload<T = unknown> {
  slug: string;
  action: string;
  version: number;
  payload: T;
  signature: Base64;
}

export interface RotateReaderPayload {
  ciphertext: Base64;
  iv: Base64;
}

export interface RotateEditorPayload {
  editor_public_keys: Base64[];
}

export interface RevokePayload {
  status: "revoked" | "archived";
  reason?: string;
}
