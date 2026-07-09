# @kodama/ksp-browser

Browser helpers for the Kodama Security Protocol. Re-exports all of `@kodama/ksp-core` plus URL fragment utilities for read-only sharing.

## Install

```bash
npm install @kodama/ksp-browser
```

## Additional Exports

### `getFragmentCapability(name: string): string | null`

Reads a capability from the current page URL hash.

```typescript
import { getFragmentCapability } from "@kodama/ksp-browser";

const readKey = getFragmentCapability("read");
// from https://note.kodama.app/wallet#read=AbCdEf...
```

The hash fragment is never sent to the server.

### `buildReadOnlyUrl(url: string, readerCapability: string): string`

Builds a shareable read-only URL.

```typescript
import { buildReadOnlyUrl } from "@kodama/ksp-browser";

const shareUrl = buildReadOnlyUrl("https://note.kodama.app/wallet", readerCapability);
// https://note.kodama.app/wallet#read=AbCdEf...
```

## Documentation

- [Integration guide](../../docs/INTEGRATION.md) — read flow with URL fragments
- [Protocol specification](../../docs/KODAMA_SECURITY_PROTOCOL.md) — sharing protocol
