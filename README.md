# AEGIS v0.4 — Connected device management

This release preserves the original local identity keys and adds a browser connection to the separately deployed AEGIS backend.

## Existing PWA
- `npm install`
- `npm test`
- `npm run build`
- `npm run dev`

Deploy the repository root as a Render **Static Site** with build command `npm run build` and publish directory `dist`.

## Backend integration
The Devices screen now connects to `https://aegis-backend-aume.onrender.com` by default. The URL can be changed in Settings. Registration exports only the public signing key, requests a one-time server challenge, signs it with the existing non-extractable private key, and stores the returned short-lived bearer token in the existing IndexedDB identity record. The token is stored locally; the server stores only its SHA-256 hash.

The Devices screen can list device records and revoke another listed record. The backend service must be deployed from `backend/` with the Render PostgreSQL Internal Database URL, `NODE_ENV=production`, and `ALLOWED_ORIGIN=https://aegis-opfa.onrender.com`. Do not commit credentials.

## Backend tests
From `backend/`, run `npm test`. The test checks P-256 key format, fingerprint format and proof verification/rejection. The backend itself requires PostgreSQL to run.

## Security limitations
This remains an early foundation, not a complete audited secure communications product. The current browser's private keys are not hardware-backed. Clearing browser data or losing the browser profile may permanently lose this identity. Backend challenges and in-memory rate limits reset on restart. Device records are grouped by the same signing-key fingerprint; this does not yet provide secure cross-device key transfer, recovery, end-to-end messaging, VPN, or multi-factor authentication. Use HTTPS and protect the database URL.


## v0.4 deployment correction
The service-worker cache is now `aegis-shell-v04`, forcing existing PWA installations to fetch the updated frontend instead of retaining the old cached app shell. The local IndexedDB identity schema and stored CryptoKey records are unchanged. Backend health reports version `0.4.0`.


## AEGIS Sentinel v0.5
Sentinel adds an authenticated security-event view and server-side event records for rejected proofs, denied authentication, successful authentication and device revocation. It displays server-observed network source metadata with an explicit warning that an IP address is not a person or exact location. Device revocation invalidates sessions for that device; Sentinel does not shut down the device or service.

This is an early security foundation, not an audited security product. Event retention currently requires database administration; no automatic expiry policy is included yet.


## Sentinel v0.5.1
Device registration/reconnection now emits an identity-scoped security event so the Sentinel log is populated after a successful reconnect.


## Sentinel v0.5.2 source-IP handling
The backend avoids recording its loopback/proxy socket address as the visitor. It accepts a single valid `X-Forwarded-For` value only; missing, malformed, or multi-hop values are stored as `unavailable`. It does not trust `X-Real-IP` or guess through a proxy chain. Confirm Render's actual header behaviour after deployment; this field is network metadata, not a person's identity or exact location.
