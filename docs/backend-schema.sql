-- Kodama Security Protocol — reference PostgreSQL schema
-- See docs/KODAMA_SECURITY_PROTOCOL.md and docs/INTEGRATION.md

-- Active place record (one row per slug)
create table places (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,                    -- normalized, validated client-side
  product_type text not null default 'note',    -- note, secret, drop, poll, room, link
  kdf text not null default 'argon2id',         -- argon2id | pbkdf2 (legacy)
  storage_mode text not null default 'legacy',  -- legacy | bundle
  ciphertext bytea,                             -- legacy single blob (null when storage_mode=bundle)
  iv text,                                      -- legacy single blob IV (null when storage_mode=bundle)
  salt text not null,                           -- base64 32-byte salt (JSON metadata)
  version integer not null default 1,           -- monotonic content version
  owner_public_key text not null,               -- base64 Ed25519 public key
  editor_public_keys jsonb not null default '[]'::jsonb,  -- base64 public keys authorized to edit
  status text not null default 'active',        -- active, archived, deleted
  visibility text not null default 'private',   -- product-specific visibility flag
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Historical versions (optional audit trail; current version also on places)
create table place_versions (
  id uuid primary key default gen_random_uuid(),
  place_id uuid not null references places(id) on delete cascade,
  version integer not null,
  ciphertext bytea not null,
  iv text not null,
  signed_by text not null,                      -- editor public key that signed this version
  signature text not null,                      -- base64 Ed25519 signature
  created_at timestamptz not null default now(),
  unique(place_id, version)
);

-- Place bundle notes (multi-tab / multi-sheet; storage_mode = bundle)
create table place_notes (
  place_id uuid not null references places(id) on delete cascade,
  version integer not null,
  note_id text not null,
  ciphertext bytea not null,
  iv text not null,
  primary key (place_id, version, note_id)
);

-- Place bundle attachments (images etc.; storage_mode = bundle)
create table place_attachments (
  place_id uuid not null references places(id) on delete cascade,
  version integer not null,
  attachment_id text not null,
  ciphertext bytea not null,
  iv text not null,
  primary key (place_id, version, attachment_id)
);

-- Owner-signed administrative actions (rotation, revoke, etc.)
create table owner_actions (
  id uuid primary key default gen_random_uuid(),
  place_id uuid not null references places(id) on delete cascade,
  action text not null,                         -- e.g. rotate-editor, revoke
  payload jsonb not null,                     -- action-specific JSON
  signature text not null,                      -- base64 owner signature
  created_at timestamptz not null default now()
);

-- Recommended indexes (add in migrations)
-- create index places_slug_idx on places(slug);
-- create index place_versions_place_id_version_idx on place_versions(place_id, version desc);
-- create index place_notes_place_id_version_idx on place_notes(place_id, version desc);
-- create index place_attachments_place_id_version_idx on place_attachments(place_id, version desc);
-- create index owner_actions_place_id_idx on owner_actions(place_id);
