# Kodama Security Protocol v1

## 1. Threat Model

### 1.1 Security Goal

Kodama is a zero-knowledge, capability-based encrypted note system.

The primary security objective is:

> Kodama should never be able to read user notes, recover user passwords, or perform protected actions without valid cryptographic authorization.

Kodama separates access into three independent permission levels:

```text
Reader
↓

Can decrypt note content.
```

```text
Editor
↓

Can decrypt and update note content.
```

```text
Owner
↓

Can read, edit, rotate capabilities, delete the note, and manage the place.
```

Ownership is represented solely by the note password.

Knowing the password grants owner privileges.

The password is never transmitted to the backend.

The password is never embedded in reader or editor share links. Read-only and editor access are granted only through URLs carrying cryptographic keys in the fragment (`#...`), never the owner password.

Kodama provides no ownership transfer feature. The password is the full ownership credential for the life of the note.

---

### 1.2 Protected Assets

Kodama treats the following as **protected assets**: material that must remain under user control and must never be readable by the backend, infrastructure operators, or unauthorized third parties.

#### Client-side secrets

These are generated or derived in the browser and must never be sent to or persisted by the backend:

- **Plaintext note** — decrypted content; present in browser memory only during use
- **Owner password** — root ownership credential; never transmitted
- **Master secret** — `Argon2id(password, salt)`; derived locally from the password
- **Content encryption key (CEK)** — symmetric key that encrypts note plaintext
- **Reader capability** — secret that unwraps the CEK for read-only access
- **Editor private key** — Ed25519 signing key; authorizes edits without granting ownership
- **Owner authentication secret** — `HKDF(master_secret, "kodama:v1:owner-auth")`; proves ownership for admin actions (ownership is password-derived, not a separate asymmetric key pair)
- **Share links** — capability-bearing URLs (fragment keys only; never the owner password)
- **Version history (plaintext)** — prior note states; meaningful only after local decryption

#### Backend may store

Public or encrypted-at-rest metadata only:

```text
slug
ciphertext
iv
salt
version
editor public key
owner authentication hash
timestamps
crypto metadata
```

#### Backend must never store

Any material that would allow decryption, impersonation, or owner actions without the user present:

```text
plaintext note
password
master secret
content encryption key
reader capability
editor private key
owner authentication secret
```

---

### 1.3 Trust Boundaries

Trusted:

```text
User browser
Web Crypto API
User password manager
HTTPS transport
```

Semi-trusted:

```text
Kodama backend
Database
Object storage
CDN
Backup systems
```

These systems may store encrypted content but must never have access to plaintext.

Untrusted:

```text
Internet
Readers
Editors
Network attackers
Database attackers
Malicious insiders
Compromised infrastructure
Search engines
Browser extensions
Shared computers
Injected JavaScript
```

---

### 1.4 Attacker Types

#### Passive Network Attacker

Can observe encrypted traffic.

Cannot break TLS.

Cannot decrypt note content.

---

#### Database Attacker

Obtains:

```text
ciphertext
salt
iv
editor public key
owner authentication hash
version
metadata
```

Cannot:

```text
decrypt notes
recover password
recover content key
recover reader capability
forge editor updates
perform owner actions
```

---

#### Malicious Backend

The backend is considered untrusted for confidentiality.

It may:

```text
delete data
refuse requests
return stale ciphertext
observe metadata
```

It must not be able to:

```text
decrypt notes
recover passwords
recover private keys
forge edits
perform owner actions
```

---

#### Reader

Reader possesses only the reader capability.

Reader can:

```text
decrypt notes
```

Reader cannot:

```text
edit
rotate capabilities
delete
become owner
```

---

#### Editor

Editor possesses:

```text
reader capability
editor private key
```

Editor can:

```text
decrypt
edit
submit signed updates
```

Editor cannot:

```text
delete
rotate capabilities
transfer ownership
change billing
perform admin actions
```

---

#### Owner

Owner knows the password.

The password derives owner authorization.

Owner can:

```text
read
edit
rotate capabilities
delete
change password
manage settings
```

---

#### Lost Password

If the password is lost, ownership is permanently lost.

Kodama cannot recover it.

This is a direct consequence of zero-knowledge security.

---

#### XSS

If malicious JavaScript executes inside the Kodama application,

it may access decrypted notes while open.

Mitigations include:

```text
strict CSP
Trusted Types
no third-party scripts
dependency review
separate marketing and secure origins
minimal secret lifetime
```

---

#### Malicious Browser Extensions

Browser extensions may inspect page memory.

Kodama cannot protect against compromised client devices.

---

### 1.5 Security Claims

Kodama can honestly claim:

```text
Notes are encrypted before leaving the browser.
Passwords never leave the browser.
Kodama cannot decrypt stored notes.
Readers cannot edit.
Editors cannot perform owner actions.
Database compromise alone does not reveal note content.
```

Kodama should not claim:

```text
Protection against compromised devices.
Protection against malicious browser extensions.
Password recovery.
Perfect anonymity.
Resistance to deletion or denial-of-service.
Independent cryptographic audit unless one has been completed.
```

## 2. Key Hierarchy

### 2.1 Design Principle

Kodama separates reading, editing, and ownership into independent cryptographic capabilities.

```text
Password
        │
        ▼
   Argon2id
        │
        ▼
 Master Secret
        │
        ├──────────────┐
        │              │
        ▼              ▼
 Reader Material   Owner Material
        │
        ▼
 Random Content Key
        │
        ▼
 Encrypt Note
```

Editing is independent.

The editor uses a signing key pair.

---

### 2.2 Root Secret

User chooses:

```text
password
```

Browser generates:

```text
salt
```

Then derives:

```text
master_secret =
Argon2id(password, salt)
```

The password never leaves the browser.

---

### 2.3 Master Secret

The master secret exists only in browser memory.

Independent values are derived using HKDF.

```text
reader_seed =
HKDF(master_secret, "kodama:v1:reader")

owner_seed =
HKDF(master_secret, "kodama:v1:owner")
```

These values are cryptographically independent.

---

### 2.4 Content Encryption Key

Kodama uses a random Data Encryption Key.

```text
content_key =
random 32 bytes
```

The content key encrypts the note using:

```text
AES-256-GCM
```

A fresh IV is generated for every encryption.

```text
iv =
random 12 bytes
```

The content key never leaves the browser in plaintext.

---

### 2.5 Reader Capability

The reader capability unlocks the content key.

Example:

```text
reader_secret
```

Reader sharing:

```text
https://note.kodama.page/note#reader_secret=...
```

The browser uses the reader secret to unwrap the content key locally.

The backend never receives the reader secret.

---

### 2.6 Editor Key Pair

The browser generates:

```text
editor_private_key
editor_public_key
```

The editor private key signs edits.

The backend stores only:

```text
editor_public_key
```

Edits are authorized using:

```text
Ed25519
```

---

### 2.7 Owner Authentication

Ownership is represented by the password.

The browser derives:

```text
owner_auth_secret =
HKDF(master_secret,
"kodama:v1:owner-auth")
```

Then computes:

```text
owner_auth_hash =
SHA-256(owner_auth_secret)
```

The backend stores only:

```text
owner_auth_hash
```

The backend never stores:

```text
password
master_secret
owner_auth_secret
```

Ownership is proven by knowledge of the password-derived owner authentication secret.

---

### 2.8 Capability Levels

#### Reader

Has:

```text
reader capability
```

Can:

```text
read
```

Cannot:

```text
edit
manage
```

---

#### Editor

Has:

```text
reader capability
editor private key
```

Can:

```text
read
edit
```

Cannot:

```text
manage
```

---

#### Owner

Has:

```text
password
```

The password derives:

```text
reader capability
owner authentication
```

Owner can:

```text
read
edit
rotate
delete
manage
```

---

### 2.9 Backend Storage

```text
ciphertext
iv
salt
version
editor_public_key
owner_auth_hash
crypto_suite
kdf_parameters
timestamps
```

No plaintext secrets are stored.

---

### 2.10 Why This Is Zero-Knowledge

Kodama stores only encrypted content and public verification material.

The backend never receives:

```text
password
content key
reader capability
editor private key
owner authentication secret
```

Therefore the backend cannot decrypt notes or impersonate the owner.

---

### 2.11 Key Rotation

Kodama supports:

```text
reader rotation
editor rotation
password rotation
full rotation
```

Password rotation replaces the owner authentication credentials derived from the password.

Reader rotation changes future read access.

Editor rotation changes future edit authorization.

Full rotation replaces every capability.

## 3. Create Note Protocol

### 3.1 Goal

The Create Note Protocol creates a new encrypted note without exposing plaintext, password, content key, reader capability, editor private key, or owner authentication secret to the backend.

---

### 3.2 User Inputs

The user enters:

```text
slug
password
plaintext note
```

The backend never receives:

```text
password
plaintext note
```

---

### 3.3 Browser Creation Steps

#### Step 1

Normalize slug.

---

#### Step 2

Generate:

```text
salt
```

---

#### Step 3

Derive:

```text
master_secret =
Argon2id(password, salt)
```

---

#### Step 4

Derive:

```text
reader_seed
owner_auth_secret
```

using HKDF.

---

#### Step 5

Generate:

```text
content_key
```

using secure random generation.

---

#### Step 6

Generate:

```text
reader_secret
```

Wrap the content key:

```text
wrapped_content_key =
Encrypt(
HKDF(reader_secret),
content_key
)
```

---

#### Step 7

Generate:

```text
editor_private_key
editor_public_key
```

---

#### Step 8

Compute:

```text
owner_auth_hash =
SHA-256(owner_auth_secret)
```

---

#### Step 9

Generate:

```text
iv
```

Encrypt:

```text
ciphertext =
AES-256-GCM(
content_key,
iv,
plaintext
)
```

---

### 3.4 Payload Sent to Backend

```json
{
  "slug": "wallet",
  "version": 1,
  "ciphertext": "...",
  "iv": "...",
  "salt": "...",
  "wrapped_content_key": "...",
  "editor_public_key": "...",
  "owner_auth_hash": "..."
}
```

The backend never receives:

```text
password
master_secret
content_key
reader_secret
editor_private_key
owner_auth_secret
```

---

### 3.5 Backend Validation

The backend validates:

```text
slug
version = 1
required fields
duplicate slug
crypto metadata
```

Then stores the encrypted note.

No password verification is required during creation because the backend stores only the owner authentication hash.

---

### 3.6 Backend Storage

The backend stores:

```text
slug
ciphertext
iv
salt
wrapped_content_key
editor_public_key
owner_auth_hash
version
timestamps
```

No plaintext secrets are stored.

---

### 3.7 Response

```json
{
  "ok": true,
  "slug": "wallet",
  "version": 1,
  "public_url": "https://note.kodama.page/wallet"
}
```

---

### 3.8 Security Properties

After creation:

```text
Backend cannot decrypt the note.
Backend cannot recover the password.
Backend cannot derive reader capability.
Backend cannot forge editor signatures.
Backend cannot perform owner actions without the password-derived owner authentication secret.
Database compromise reveals only encrypted data and public metadata.
```
## 4. Read Protocol

### 4.1 Goal

The Read Protocol allows a user with valid read access to decrypt note content entirely within the browser.

The backend stores only encrypted data and never participates in decryption.

---

### 4.2 Access Levels

Kodama supports three access levels.

#### Owner

Owner knows:

```text
password
```

The browser derives:

```text
master_secret
↓

reader capability
```

Owner can read every version of the note.

---

#### Editor

Editor possesses:

```text
reader capability
editor private key
```

Editor can decrypt and edit the note.

---

#### Reader

Reader possesses:

```text
reader capability
```

Reader can decrypt the note but cannot modify it.

---

### 4.3 Owner Read Flow

```text
Owner opens note URL
↓
Backend returns:

ciphertext
iv
salt
wrapped_content_key
version
crypto metadata

↓
Owner enters password

↓
Browser derives:

master_secret
↓

reader capability

↓
Browser unwraps content_key

↓

Browser decrypts ciphertext locally

↓

Plaintext appears
```

The backend never receives:

```text
password
master_secret
reader capability
content_key
plaintext
```

---

### 4.4 Reader Read Flow

Reader receives a sharing link.

Example:

```text
https://note.kodama.page/wallet#reader_secret=...
```

Flow:

```text
Reader opens URL
↓

Browser extracts reader_secret from URL fragment

↓

Backend receives only:

/wallet

↓

Backend returns:

ciphertext
wrapped_content_key
iv
version
salt

↓

Browser derives unwrap key

↓

Browser unwraps content_key

↓

Browser decrypts ciphertext

↓

Plaintext displayed
```

The backend never receives the reader secret because URL fragments are not transmitted during HTTP requests.

---

### 4.5 Browser Decryption

The browser performs:

```text
unwrap_key =
HKDF(reader_secret)

↓

content_key =
Decrypt(
wrapped_content_key
)

↓

plaintext =
AES-256-GCM-Decrypt(
content_key,
ciphertext,
iv
)
```

All cryptographic operations occur locally.

---

### 4.6 Backend Response

Endpoint:

```text
GET /api/places/:slug
```

Response:

```json
{
  "slug": "wallet",
  "version": 8,
  "ciphertext": "...",
  "wrapped_content_key": "...",
  "iv": "...",
  "salt": "...",
  "editor_public_key": "...",
  "crypto_suite": "AES-256-GCM",
  "kdf": "Argon2id"
}
```

No authentication is required to download encrypted data.

Only possession of a valid reader capability allows successful decryption.

---

### 4.7 Security Properties

The Read Protocol guarantees:

```text
Notes are decrypted only inside the browser.
The backend never receives plaintext.
The backend never receives passwords.
Readers cannot edit.
Database compromise alone cannot reveal note content.
```

---

## 5. Edit Protocol

### 5.1 Goal

The Edit Protocol allows the active editor to update encrypted content while preventing unauthorized modifications.

Kodama supports one active editor per note.

---

### 5.2 Editor Capability

Editor possesses:

```text
reader capability
editor private key
```

Editor can:

```text
decrypt
edit
encrypt
sign updates
```

Editor cannot:

```text
delete
rotate capabilities
change password
perform owner actions
```

---

### 5.3 Edit Flow

```text
Editor opens note
↓

Browser downloads encrypted note

↓

Browser unwraps content_key

↓

Browser decrypts note

↓

Editor modifies content

↓

Browser generates fresh IV

↓

Browser encrypts updated note

↓

Browser creates canonical edit message

↓

Browser signs message with editor_private_key

↓

Backend verifies signature

↓

Backend verifies version

↓

Backend stores new ciphertext

↓

Version increments
```

---

### 5.4 Canonical Edit Message

The browser signs:

```json
{
  "protocol": "kodama-note",
  "protocol_version": 1,
  "action": "edit-note",
  "slug": "wallet",
  "old_version": 8,
  "new_version": 9,
  "ciphertext_hash": "...",
  "iv": "...",
  "request_id": "uuid...",
  "timestamp": "2026-07-06T00:00:00Z"
}
```

Signature:

```text
Ed25519(editor_private_key)
```

---

### 5.5 Backend Validation

Backend accepts an edit only if:

```text
editor signature is valid
editor public key matches stored key
old_version equals current version
new_version = old_version + 1
request_id has not been used
ciphertext_hash matches uploaded ciphertext
```

If validation fails:

```text
reject update
```

---

### 5.6 Edit Request

Endpoint:

```text
POST /api/places/:slug/edit
```

Request:

```json
{
  "old_version": 8,
  "new_version": 9,
  "ciphertext": "...",
  "iv": "...",
  "ciphertext_hash": "...",
  "request_id": "uuid...",
  "signature": "..."
}
```

The backend never receives:

```text
plaintext
password
reader capability
content_key
editor private key
```

---

### 5.7 Conflict Detection

Only one version may become current.

If another edit already updated the note:

```json
{
  "ok": false,
  "error": "stale_version",
  "current_version": 9
}
```

The browser should fetch the latest encrypted version before retrying.

---

### 5.8 Security Properties

The Edit Protocol ensures:

```text
Readers cannot edit.
Backend cannot forge edits.
Replay attacks are rejected.
Version conflicts are detected.
Permission enforcement is cryptographic.
```

---

## 6. Owner/Admin Protocol

### 6.1 Goal

The Owner/Admin Protocol authorizes operations that permanently change access or cryptographic capabilities.

Ownership is represented entirely by the password.

The backend never stores or receives the password.

---

### 6.2 Owner Authentication

Ownership is represented solely by the password.

When the owner wants to perform administrative actions:

```text
Owner enters password
↓

Browser derives:

master_secret

↓

owner authentication material

↓

Browser proves ownership to the backend

↓

Backend creates a short-lived authenticated owner session

↓

Browser receives an owner session token
```

The password never leaves the browser.

The owner authentication material is used only during session creation.

After authentication succeeds, subsequent owner actions use the temporary owner session token instead of repeating the authentication process.

Recommended session lifetime:

```text
15–30 minutes of inactivity
```

The owner should be prompted for the password again after the session expires.

---

### 6.3 Owner Capabilities

Only the owner may perform:

```text
delete note
change password
rotate reader capability
rotate editor key
rotate all capabilities
change permanent settings
```

Editors and readers cannot perform these actions.

---

### 6.4 Owner Action Flow

Example: Rotate Editor Key.

```text
Owner opens Settings
↓

Owner enters password

↓

Browser derives owner authentication material

↓

Browser authenticates with backend

↓

Backend creates owner session

↓

Browser generates new editor key pair

↓

Browser builds owner action request

↓

Browser sends request using owner session token

↓

Backend validates owner session

↓

Backend performs action

↓

Owner action sequence increments
```
---

### 6.5 Owner Request

Endpoint:

```text
POST /api/places/:slug/owner-action
```

Request:

```json
{
  "owner_session_token": "...",
  "owner_action_sequence": 14,
  "action": "rotate-editor-key",
  "payload": {
    "new_editor_public_key": "..."
  },
  "request_id": "uuid..."
}
```

The backend verifies:

```text
owner session is valid
owner session has not expired
owner session belongs to this place
owner_action_sequence is correct
request_id has not been used
payload is valid
```

The session token is temporary and does not reveal the owner's password or any cryptographic keys.

If the session expires, the owner must authenticate again by entering the password.
---

### 6.6 Backend Validation

Backend accepts an owner action only if:

```text
owner authentication succeeds
owner_action_sequence is correct
request_id has not been used
action is supported
payload is valid
```

Otherwise:

```text
reject request
```

---

### 6.7 Security Properties

The Owner/Admin Protocol guarantees:

```text
Only knowledge of the password grants owner privileges.
The password is never transmitted to the backend.
The password is never included in reader or editor share links.
Editors cannot become owners.
Readers cannot become owners.
Administrative actions require successful owner authentication.
Password rotation revokes the previous password's owner privileges.
Kodama provides no ownership transfer workflow.
```
## 7. Sharing Protocol

### 7.1 Goal

Kodama uses a capability-based sharing model.

The owner's password is never shared and never appears in a share link.

Instead, the owner grants access by sharing URLs that carry cryptographic keys in the fragment (`#...`). The fragment is processed locally by the browser and is never sent to the backend.

Kodama supports three permission levels:

```text
Owner
Editor
Reader
```

Each permission level is cryptographically independent.

Sharing read access never grants edit access.

Sharing edit access never grants ownership.

Kodama provides no ownership transfer feature. There is no supported workflow to reassign ownership to another person.

---

### 7.2 Permission Model

#### Owner

Owner knows:

```text
password
```

The password derives:

```text
reader capability
owner session authentication
```

The owner can:

```text
read
edit
change password
rotate reader capability
rotate editor key
rotate all capabilities
delete note
manage settings
```

---

#### Editor

Editor possesses:

```text
reader capability
editor private key
```

The editor can:

```text
read
decrypt
edit
encrypt
sign updates
```

The editor cannot:

```text
change password
rotate capabilities
delete note
perform owner actions
```

Kodama supports only one active editor.

---

#### Reader

Reader possesses:

```text
reader capability
```

The reader can:

```text
read
decrypt
```

The reader cannot:

```text
edit
manage
delete
rotate
```

---

### 7.3 Reader Sharing

The owner creates a read-only sharing link.

The browser generates:

```text
reader_secret
```

The browser wraps the content encryption key.

```text
wrapped_content_key =
Encrypt(
    HKDF(reader_secret),
    content_key
)
```

The backend stores:

```text
wrapped_content_key
content_key_epoch
```

The browser generates:

```text
https://note.kodama.page/my-note#reader_secret=...
```

Everything after `#` remains inside the browser and is never transmitted to the backend.

When the reader opens the link:

```text
Browser extracts reader_secret
↓

Downloads ciphertext
↓

Downloads wrapped_content_key
↓

Unwraps content_key
↓

Decrypts note locally
```

The backend never receives:

```text
reader_secret
content_key
plaintext
```

---

### 7.4 Editor Sharing

The owner may grant edit access.

The browser generates:

```text
editor_private_key
editor_public_key
```

The owner establishes the new editor during an authenticated owner session.

The backend stores only:

```text
editor_public_key
```

The browser generates an editor share URL containing only capability material in the fragment, for example:

```text
https://note.kodama.page/my-note#reader_secret=...&editor_key=...
```

The editor URL never contains the owner password.

The editor receives:

```text
reader capability
editor private key
```

Both are delivered through the share URL fragment or an equivalent offline capability package — never through the password.

The editor can decrypt the note and submit signed updates.

The backend verifies every update using the stored editor public key.

---

### 7.5 Sharing Limitations

Kodama intentionally does not attempt to control information after it has been decrypted.

Once someone has successfully decrypted a note, they may:

```text
copy the text
take screenshots
print the page
save local copies
```

This is outside the scope of cryptography.

Cryptography protects access to encrypted data.

It cannot prevent users from copying plaintext after legitimate access.

---

### 7.6 Backend Knowledge

The backend stores only encrypted and public information.

The backend may know:

```text
slug
ciphertext
wrapped_content_key
version
editor_public_key
timestamps
crypto metadata
```

The backend never knows:

```text
password
reader_secret
content_key
editor_private_key
plaintext
```

---

### 7.7 Security Properties

The Sharing Protocol guarantees:

```text
Owner password is never shared.
Owner password is never embedded in reader or editor share URLs.
Reader and editor access is granted only through URLs carrying cryptographic keys.
Readers cannot edit.
Editors cannot perform owner actions.
Backend cannot decrypt shared notes.
Backend cannot create valid editor signatures.
Sharing permissions are cryptographically separated.
Kodama provides no ownership transfer workflow.
```

---

## 8. Rotation Protocol

### 8.1 Goal

Kodama does not implement revocation.

Instead, it uses rotation.

Rotation replaces cryptographic capabilities with new ones.

Future versions of the note become inaccessible using previous capabilities.

Rotation cannot erase information that has already been decrypted.

---

### 8.2 Rotation Types

Kodama supports:

```text
Reader Rotation
Editor Rotation
Password Rotation
Full Rotation
```

---

### 8.3 Reader Rotation

Reader rotation is used when:

```text
A read-only link has been shared accidentally.
A reader should no longer access future versions.
The owner wants a fresh sharing link.
```

Flow:

```text
Owner authenticates
↓

Browser decrypts current note

↓

Generate new content_key

↓

Generate new reader_secret

↓

Wrap new content_key

↓

Re-encrypt note

↓

Upload new ciphertext

↓

Increment content_key_epoch
```

Future note versions require the new reader capability.

Old reader links can no longer decrypt future ciphertext.

---

### 8.4 Editor Rotation

Editor rotation replaces the active editor.

Flow:

```text
Owner authenticates

↓

Browser generates new editor key pair

↓

Backend stores new editor_public_key

↓

Old editor key becomes invalid for future edits
```

The previous editor can no longer submit accepted updates.

Editor rotation does not automatically remove read access.

If the editor also possessed the reader capability, perform Reader Rotation as well.

---

### 8.5 Password Rotation

The password is the sole ownership credential.

Changing the password replaces the owner authentication material derived from it.

Flow:

```text
Owner authenticates

↓

Owner chooses new password

↓

Browser derives new master_secret

↓

Browser derives new owner authentication material

↓

Backend updates owner authentication record

↓

Owner session is refreshed
```

The old password immediately loses owner privileges.

Password rotation does not require re-encrypting the note.

However, if password compromise is suspected, Reader Rotation and Editor Rotation should also be performed.

---

### 8.6 Full Rotation

Full Rotation replaces every active capability.

Flow:

```text
Owner authenticates

↓

Decrypt note

↓

Generate new content_key

↓

Generate new reader_secret

↓

Generate new editor key pair

↓

Generate fresh IV

↓

Re-encrypt note

↓

Wrap new content_key

↓

Upload updated ciphertext

↓

Replace editor_public_key

↓

Increment content_key_epoch
```

After Full Rotation:

```text
Old reader links cannot decrypt future versions.

Old editor keys cannot edit.

Old password no longer grants owner privileges if the password was also changed.
```

---

### 8.7 Backend Validation

Every rotation request must verify:

```text
Valid owner session

Correct owner action sequence

Unused request_id

Valid payload

Current version matches
```

If any validation fails:

```text
Reject rotation
```

---

### 8.8 Rotation Limitations

Rotation protects future access only.

Rotation cannot prevent access to information that has already been legitimately decrypted.

Rotation cannot prevent:

```text
Screenshots

Copied text

Printed copies

Compromised user devices

Malicious browser extensions

Malicious JavaScript running on the client
```

---

### 8.9 Security Properties

Rotation guarantees:

```text
Future reader access can be replaced.

Future editor authorization can be replaced.

Ownership changes immediately after password change.

Old cryptographic capabilities cannot access future protected versions.
```

---

## 9. Access Loss Limitations

### 9.1 Zero-Knowledge Model

Kodama never stores:

```text
password

master_secret

reader_secret

content_key

editor_private_key

plaintext note
```

Therefore, Kodama cannot recover these secrets.

This limitation is fundamental to zero-knowledge encryption.

---

### 9.2 Lost Password

If the owner forgets the password:

```text
Owner access is permanently lost.
```

Kodama cannot recover the password.

Kodama cannot reset the password.

Kodama cannot restore ownership.

---

### 9.3 Lost Reader Capability

If a reader loses the sharing link:

```text
Owner generates a new reader capability.

Owner shares a new link.
```

No password change is required.

---

### 9.4 Lost Editor Private Key

If the editor loses the private key:

```text
Owner performs Editor Rotation.

↓

Browser generates a new editor key pair.

↓

New editor credentials are shared.
```

The old editor key becomes invalid for future edits.

---

### 9.5 Why Kodama Cannot Recover Notes

Kodama never possesses the information required to decrypt notes.

The backend stores only encrypted content and public verification material.

Because the password and cryptographic secrets remain entirely under user control, Kodama cannot recover lost access, even as the service provider.

This limitation is the direct consequence of providing true zero-knowledge security.

---

### 9.6 User-Facing Explanation

> Your note is encrypted before it leaves your browser. Kodama never receives your password or your cryptographic secrets. Because only you possess the information required to unlock your note, Kodama cannot recover lost passwords or restore access if they are forgotten.

---

### 9.7 Investor Explanation

> Kodama implements a zero-knowledge security architecture in which ownership, editing, and reading are cryptographically separated. The service stores encrypted content and public verification data only, allowing authorization and collaboration without ever possessing the user's password or plaintext. This architecture prevents both infrastructure compromise and service operators from accessing protected content while maintaining fine-grained permission control.

---

## 10. Backend Database Schema

### 10.1 Design Principle

Kodama separates encrypted content from metadata.

Large encrypted notes are stored in object storage.

The PostgreSQL database stores only metadata, cryptographic information, routing information, and version history.

This allows Kodama to efficiently support notes larger than 10 MB while keeping database operations lightweight.

---

### 10.2 Object Storage

Encrypted note content is stored in object storage.

Example object path:

```text
notes/{place_id}/v{version}.bin
```

Object contents:

```text
ciphertext
```

The storage service never receives:

```text
plaintext
password
content key
reader capability
private keys
```

The storage service stores encrypted bytes only.

---

### 10.3 places

```sql
create table places (

    id uuid primary key default gen_random_uuid(),

    slug text not null unique,

    product_type text not null default 'note',

    current_version integer not null default 1,

    current_object_key text not null,

    current_ciphertext_sha256 text not null,

    iv text not null,

    salt text not null,

    wrapped_content_key text not null,

    editor_public_key text not null,

    owner_auth_hash text not null,

    owner_auth_salt text not null,

    content_key_epoch integer not null default 1,

    owner_action_sequence integer not null default 0,

    crypto_suite text not null,

    kdf_algorithm text not null,

    kdf_parameters jsonb not null,

    status text not null default 'active',

    created_at timestamptz not null default now(),

    updated_at timestamptz not null default now()

);
```

---

### 10.4 place_versions

```sql
create table place_versions (

    id uuid primary key default gen_random_uuid(),

    place_id uuid not null references places(id) on delete cascade,

    version integer not null,

    object_key text not null,

    ciphertext_sha256 text not null,

    iv text not null,

    content_key_epoch integer not null,

    editor_signature text not null,

    editor_request_id uuid not null,

    created_at timestamptz not null default now(),

    unique(place_id, version)

);
```

Purpose:

```text
Version history
Conflict detection
Audit trail
Rollback
```

---

### 10.5 owner_actions

```sql
create table owner_actions (

    id uuid primary key default gen_random_uuid(),

    place_id uuid not null references places(id),

    sequence integer not null,

    action text not null,

    payload jsonb not null,

    request_id uuid not null,

    created_at timestamptz not null default now(),

    unique(place_id, sequence)

);
```

Purpose:

```text
Audit owner operations
Prevent replay
Security logging
```

---

### 10.6 orders

```sql
create table orders (

    id uuid primary key default gen_random_uuid(),

    place_id uuid references places(id),

    provider text not null,

    provider_order_id text,

    amount_cents integer not null,

    currency text not null,

    status text not null,

    created_at timestamptz default now(),

    updated_at timestamptz default now()

);
```

---

### 10.7 payments

```sql
create table payments (

    id uuid primary key default gen_random_uuid(),

    order_id uuid references orders(id),

    provider text not null,

    provider_payment_id text,

    amount_cents integer not null,

    currency text not null,

    status text not null,

    raw_event jsonb,

    created_at timestamptz default now()

);
```

---

### 10.8 Backend Storage Summary

The backend stores:

```text
Encrypted object location
Ciphertext hash
IV
Salt
Wrapped content key
Editor public key
Owner authentication hash
Version metadata
Payment metadata
Audit metadata
```

The backend never stores:

```text
Plaintext note
Password
Master secret
Reader capability
Content key
Editor private key
```
## 11. API Message Format

### 11.1 Design Principles

All API requests operate on encrypted data.

The backend never processes plaintext.

Large ciphertext is uploaded directly to object storage.

The database stores metadata only.

Every edit is versioned.

---

### 11.2 Create Note

```
POST /api/places/create
```

Request:

```json
{
  "slug": "wallet",
  "product_type": "note",
  "version": 1,
  "object_key": "notes/uuid/v1.bin",
  "ciphertext_sha256": "...",
  "ciphertext_size": 12455382,
  "iv": "...",
  "salt": "...",
  "wrapped_content_key": "...",
  "editor_public_key": "...",
  "owner_auth_hash": "..."
}
```

Backend:

```text
Validates slug

Validates metadata

Registers note

Stores metadata

Object already exists in storage
```

---

### 11.3 Read Note

```
GET /api/places/:slug
```

Response:

```json
{
  "version": 8,
  "object_key": "notes/.../v8.bin",
  "ciphertext_sha256": "...",
  "ciphertext_size": 12548102,
  "iv": "...",
  "salt": "...",
  "wrapped_content_key": "...",
  "editor_public_key": "...",
  "crypto_suite": "AES-256-GCM",
  "kdf": "Argon2id"
}
```

Browser downloads ciphertext directly from object storage.

---

### 11.4 Edit Note

```
POST /api/places/:slug/edit
```

Request:

```json
{
  "old_version": 8,
  "new_version": 9,
  "object_key": "notes/.../v9.bin",
  "ciphertext_sha256": "...",
  "ciphertext_size": 12888551,
  "iv": "...",
  "request_id": "...",
  "signature": "..."
}
```

Backend validates:

```text
Editor signature

Version

Request uniqueness

Ciphertext metadata
```

Then updates metadata.

---

### 11.5 Owner Action

```
POST /api/places/:slug/owner-action
```

Request:

```json
{
  "owner_session_token": "...",
  "owner_action_sequence": 15,
  "action": "rotate-editor",
  "payload": {
    "new_editor_public_key": "..."
  },
  "request_id": "..."
}
```

Backend validates:

```text
Owner session

Sequence

Request uniqueness
```

---

### 11.6 Upload Flow

Large encrypted files should not be uploaded through the API.

Recommended flow:

```text
Browser encrypts note

↓

Request upload URL

↓

Backend returns signed upload URL

↓

Browser uploads ciphertext directly to object storage

↓

Browser calls Create/Edit API with metadata only
```

Advantages:

```text
Supports 100MB+

Supports resumable upload

Reduces backend bandwidth

Scales with CDN

No API payload limits
```

---

### 11.7 Payment API

Payment APIs remain unchanged.

Payments never receive encryption material.

Payment providers never receive plaintext note content.
## 12. Security Claims

### 12.1 Claims Kodama Can Make

Kodama can accurately claim:

1. Notes are encrypted before leaving the browser.
2. Kodama never receives user passwords.
3. Kodama never stores plaintext note content.
4. Kodama stores encrypted notes separately from metadata.
5. Readers cannot edit notes.
6. Editors cannot perform owner actions.
7. Only the password grants owner privileges.
8. The backend cannot decrypt stored notes.
9. The backend cannot forge editor updates because it does not possess the editor private key.
10. Database compromise alone does not reveal note content.
11. Object storage compromise alone does not reveal note content.
12. Payment processing is isolated from encrypted content.
13. Large notes are handled without exposing plaintext to the backend.
14. All cryptographic operations occur inside the user's browser.

---

### 12.2 Claims Kodama Must Not Make

Kodama should never claim:

1. Protection against compromised user devices.
2. Protection against malicious browser extensions.
3. Protection against malicious client-side JavaScript running in the Kodama origin.
4. Password recovery.
5. Recovery of encrypted notes without the password.
6. Perfect anonymity.
7. Resistance to censorship or deletion.
8. Prevention of copying, screenshots, or printing after decryption.
9. Independent cryptographic validation unless the protocol has been externally audited.

---

### 12.3 End-User Explanation

> Your note is encrypted inside your browser before it is uploaded. Kodama stores only encrypted data and the metadata required to retrieve it. Your password never leaves your device, and only someone with the correct password or a valid shared capability can access the note. Even if Kodama's database or storage systems are compromised, attackers cannot read your notes without the cryptographic secrets that remain under your control.

---

### 12.4 Investor Explanation

> Kodama Note implements a zero-knowledge, capability-based security architecture designed for both security and scalability. Large encrypted notes are stored in object storage, while PostgreSQL stores only metadata and public verification information. Reading, editing, and ownership are cryptographically separated, allowing the backend to authorize operations without ever possessing plaintext content, user passwords, or private signing keys. This architecture supports large encrypted documents efficiently while preserving end-to-end confidentiality.
