import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ARGON2ID_PARAMS,
  PBKDF2_ITERATIONS,
  bundleDigestFromPlaceBundle,
  bytesToBase64,
  bytesToHex,
  compressNoteText,
  createNoteMessage,
  createPlaceBundleMessage,
  createPlaceBundlePayload,
  deriveKspMaterial,
  deriveMasterSecretArgon2id,
  deriveMasterSecretPbkdf2,
  encryptBytes,
  keyPairFromSeed,
  signMessage,
} from "../src/index.js";
import { setRandomOverride } from "../src/random.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, "../../../test-vectors");

const FIXED_SALT = new Uint8Array(32).fill(0x42);
const FIXED_IV = new Uint8Array(12).fill(0x11);

setRandomOverride((length) => {
  if (length === 32) return FIXED_SALT;
  if (length === 12) return FIXED_IV;
  return new Uint8Array(length).fill(0xaa);
});

const password = "correct horse battery staple";
const slug = "wallet";
const productType = "note";
const version = 1;
const plaintext = "hello kodama";

const argon2Master = await deriveMasterSecretArgon2id(password, FIXED_SALT);
const pbkdf2Master = await deriveMasterSecretPbkdf2(password, FIXED_SALT);

const argon2Material = deriveKspMaterial(argon2Master);
const pbkdf2Material = deriveKspMaterial(pbkdf2Master);

const editor = await keyPairFromSeed(argon2Material.editorSeed);
const owner = await keyPairFromSeed(argon2Material.ownerSeed);

const compressed = await compressNoteText(plaintext);

const encrypted = await encryptBytes(
  compressed,
  argon2Material.readKey,
  `${slug}:${version}:${productType}`
);

const saltB64 = bytesToBase64(FIXED_SALT);
const ivB64 = bytesToBase64(FIXED_IV);
const createMessage = createNoteMessage({
  slug,
  productType,
  version,
  kdf: "argon2id",
  ciphertext: encrypted.ciphertext,
  iv: ivB64,
  salt: saltB64,
  ownerPublicKey: owner.publicKey,
  editorPublicKeys: [editor.publicKey],
});
const ownerSignature = await signMessage(owner.privateKey, createMessage);

const bundleCreated = await createPlaceBundlePayload({
  slug,
  password,
  productType,
  notes: [
    { id: "tab-a", plaintext: "tab a content" },
    { id: "tab-b", plaintext: "tab b content" },
  ],
});
const bundleDigest = bundleDigestFromPlaceBundle(bundleCreated.bundle);
const bundleCreateMessage = createPlaceBundleMessage({
  slug,
  productType,
  version,
  kdf: "argon2id",
  bundleDigest,
  salt: saltB64,
  ownerPublicKey: owner.publicKey,
  editorPublicKeys: [editor.publicKey],
});

const vectors = {
  version: "ksp-v1",
  generated_at: new Date().toISOString(),
  kdf: {
    argon2id: {
      params: ARGON2ID_PARAMS,
      password,
      salt_hex: bytesToHex(FIXED_SALT),
      master_secret_hex: bytesToHex(argon2Master),
      read_key_hex: bytesToHex(argon2Material.readKey),
      editor_seed_hex: bytesToHex(argon2Material.editorSeed),
      owner_seed_hex: bytesToHex(argon2Material.ownerSeed),
    },
    pbkdf2: {
      iterations: PBKDF2_ITERATIONS,
      password,
      salt_hex: bytesToHex(FIXED_SALT),
      master_secret_hex: bytesToHex(pbkdf2Master),
      read_key_hex: bytesToHex(pbkdf2Material.readKey),
    },
  },
  compression: {
    algorithm: "gzip",
    plaintext,
    compressed_hex: bytesToHex(compressed),
  },
  encryption: {
    plaintext,
    slug,
    product_type: productType,
    version,
    aad: `${slug}:${version}:${productType}`,
    iv_hex: bytesToHex(FIXED_IV),
    iv: ivB64,
    ciphertext_hex: bytesToHex(encrypted.ciphertext),
  },
  create_note: {
    slug,
    product_type: productType,
    version,
    kdf: "argon2id",
    salt: saltB64,
    owner_public_key: owner.publicKey,
    editor_public_keys: [editor.publicKey],
    iv: ivB64,
    ciphertext_hex: bytesToHex(encrypted.ciphertext),
    canonical_message: createMessage,
    owner_signature: ownerSignature,
  },
  create_place_bundle: {
    slug,
    product_type: productType,
    version,
    kdf: "argon2id",
    salt: saltB64,
    owner_public_key: bundleCreated.metadata.owner_public_key,
    editor_public_keys: bundleCreated.metadata.editor_public_keys,
    notes: bundleCreated.metadata.notes,
    attachments: bundleCreated.metadata.attachments,
    bundle_digest: bundleDigest,
    canonical_message: bundleCreateMessage,
    owner_signature: bundleCreated.metadata.owner_signature,
    note_ciphertext_hex: Object.fromEntries(
      bundleCreated.bundle.notes.map((note) => [
        note.id,
        bytesToHex(note.ciphertext),
      ])
    ),
  },
  slug: {
    cases: [
      { input: "Wallet", normalized: "wallet", valid: true },
      { input: "  My Note  ", normalized: "my-note", valid: true },
      { input: "ab", normalized: "ab", valid: false, error: "invalid_format" },
      { input: "admin", normalized: "admin", valid: false, error: "reserved_slug" },
    ],
  },
};

writeFileSync(
  join(vectorsDir, "v1.json"),
  JSON.stringify(vectors, null, 2) + "\n"
);
console.log("Wrote test-vectors/v1.json");
