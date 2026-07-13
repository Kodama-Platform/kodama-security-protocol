# @kodama.page/ksp-server

Server-side verification helpers for the Kodama Security Protocol. Use this package in API routes, workers, or backend services to validate signed payloads without handling secrets.

## Install

```bash
npm install @kodama.page/ksp-server
```

## Exports

| Function | Purpose |
|----------|---------|
| `verifyCreateNotePayload` | Verify owner signature on place creation |
| `verifyEditPayload` | Verify editor signature, version, and authorized key |
| `verifyOwnerActionPayload` | Verify owner signature on admin actions |
| `verifyRotateReaderAction` | Verify reader-capability rotation action |
| `verifyRotatePasswordAction` | Verify password rotation action |
| `verifyRotateEditorAction` | Verify editor key rotation action |
| `verifyRevokeAction` | Verify revoke/archive action |
| `OWNER_ACTIONS` | Action name constants (`rotate-reader`, `rotate-editor`, `revoke`) |
| `normalizeSlug` | Normalize slug input |
| `validateSlug` | Validate slug format and reserved names |

## Example

```typescript
import {
  verifyCreateNotePayload,
  verifyEditPayload,
  verifyRotateReaderAction,
} from "@kodama.page/ksp-server";

app.post("/api/places/:slug/owner-actions", async (req, res) => {
  const place = await getPlace(req.params.slug);

  if (req.body.action === "rotate-reader") {
    const valid = await verifyRotateReaderAction(
      req.body,
      place.owner_public_key,
      place.version
    );
    if (!valid) return res.status(400).json({ error: "invalid_action" });
    await db.places.update(place.slug, {
      ciphertext: req.body.payload.ciphertext,
      iv: req.body.payload.iv,
    });
    return res.json({ ok: true });
  }
});
```

This package does **not** decrypt content or derive keys. The server never needs the password or read capability.

## Documentation

- [Integration guide](../../docs/INTEGRATION.md) — server-side flows
- [Backend schema](../../docs/backend-schema.sql) — reference database tables
