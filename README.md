# Kodama Security Protocol (KSP)

The Kodama Security Protocol (KSP) is the official shared security framework for the Kodama ecosystem.

KSP provides a zero-knowledge, capability-based architecture for encryption, sharing, editing, and ownership across Kodama products such as Note, Secret, Drop, Link, Poll, and Room.

## Core Ideas

- Password stays on the client.
- Content is encrypted before upload.
- Backend stores ciphertext and public verification keys only.
- Reading, editing, and ownership are separated into independent capabilities.
- Servers can verify permissions without reading user content.

## Repository Layout

```text
kodama-security-protocol/
├── packages/
│   ├── core/          @kodama/ksp-core   — crypto primitives and protocol logic
│   ├── browser/       @kodama/ksp-browser — browser helpers (URL fragments, re-exports)
│   └── server/        @kodama/ksp-server  — server-side verification helpers
├── docs/
│   ├── KODAMA_SECURITY_PROTOCOL.md  — protocol specification
│   ├── INTEGRATION.md               — integration guide for apps and backends
│   ├── AUDIT.md                     — implementation audit and known gaps
│   └── backend-schema.sql           — reference PostgreSQL schema
├── examples/note/     — minimal create-note example
└── test-vectors/      — interoperability vectors (planned)
```

## Packages

| Package | Purpose |
|---------|---------|
| [`@kodama/ksp-core`](packages/core) | Key derivation, encryption, signing, message canonicalization, payload builders and verifiers |
| [`@kodama/ksp-browser`](packages/browser) | Re-exports core plus URL fragment helpers for read-only sharing |
| [`@kodama/ksp-server`](packages/server) | Re-exports verification and slug helpers for backend use |

## Quick Start

### Install

```bash
git clone <repo-url>
cd kodama-security-protocol
npm install
npm run build
npm test
```

### Create a Note (client-side)

```typescript
import { createNotePayload } from "@kodama/ksp-core";

const result = await createNotePayload({
  slug: "wallet",
  password: "user-chosen-password",
  plaintext: "My private note",
});

// Upload to backend — no secrets in this object
await fetch("/api/places", {
  method: "POST",
  body: JSON.stringify(result.payload),
});

// Store client-side only — never send to the server
const secrets = {
  readerCapability: result.readerCapability,
  editorPrivateKey: result.editorPrivateKey,
  ownerPrivateKey: result.ownerPrivateKey,
};
```

### Verify on the Server

```typescript
import { verifyCreateNotePayload, verifyEditPayload } from "@kodama/ksp-server";

const ok = await verifyCreateNotePayload(incomingPayload);
if (!ok) throw new Error("invalid create signature");
```

See [`examples/note/create-note.ts`](examples/note/create-note.ts) and [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for full flows.

## Documentation

| Document | Description |
|----------|-------------|
| [Protocol Specification](docs/KODAMA_SECURITY_PROTOCOL.md) | Threat model, key hierarchy, message formats, sharing, rotation |
| [Integration Guide](docs/INTEGRATION.md) | Step-by-step flows for create, read, edit, and owner actions |
| [Audit Report](docs/AUDIT.md) | Implementation status, gaps, and recommendations |
| [Backend Schema](docs/backend-schema.sql) | Reference database tables |

## Architecture Overview

```text
┌─────────────┐     ciphertext + public keys      ┌─────────────┐
│   Browser   │ ──────────────────────────────► │   Backend   │
│  (ksp-core) │ ◄────────────────────────────── │ (ksp-server)  │
└─────────────┘     encrypted blob + metadata   └─────────────┘
       │
       │ password, read capability, private keys
       ▼
  never leaves client
```

**Capability separation**

| Role | Material | Can read | Can edit | Can administer |
|------|----------|----------|----------|----------------|
| Owner | Password → master secret | Yes | Yes (via derived editor key) | Yes |
| Editor | Read capability + editor private key | Yes | Yes | No |
| Reader | Read capability only (URL fragment) | Yes | No | No |
| Server | Public keys + ciphertext | No | Verifies only | Verifies only |

## Development

```bash
npm run build      # build all packages
npm run test       # run workspace tests
npm run typecheck  # typecheck all packages
```

Workspaces are defined in the root `package.json`. Each package under `packages/` has its own `package.json` and `tsconfig.json`.

## Security Notice

KSP is a security-sensitive protocol. Before production launch, the implementation and protocol should receive independent security review.

See [`docs/AUDIT.md`](docs/AUDIT.md) for the current implementation audit, including known gaps between the specification and code.
