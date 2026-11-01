# AEGIS backend v0.2

Separate Node.js API service for cryptographic device registration, authentication, device listing and revocation. The browser's private keys never leave the device.

## Deploy on Render
1. Create a PostgreSQL database in Render.
2. Create a separate **Web Service** from the same GitHub repository.
3. Set **Root Directory** to `backend`, **Build Command** to `npm install`, and **Start Command** to `npm start`.
4. Add environment variables:
   - `DATABASE_URL`: Render PostgreSQL Internal Database URL (secret)
   - `NODE_ENV`: `production`
   - `ALLOWED_ORIGIN`: `https://aegis-opfa.onrender.com`
5. Keep the existing Static Site unchanged.

## API
- `GET /health`
- `POST /v1/challenges` — `{ "publicKey": "base64 raw P-256 public key" }`
- `POST /v1/devices/register` — `{ "publicKey", "challengeId", "signature", "label" }`
- `POST /v1/devices/authenticate` — `{ "publicKey", "challengeId", "signature" }`
- `GET /v1/devices` — bearer token required
- `POST /v1/devices/{deviceId}/revoke` — bearer token required

The client signs the exact challenge message with ECDSA P-256/SHA-256. Signatures are base64 IEEE-P1363 (64 bytes). Challenges expire after two minutes and are single-use. Bearer tokens are random, stored only as SHA-256 hashes in PostgreSQL, and expire after 30 days.

## Security status / limitations
This is an early backend foundation, not a completed or independently audited secure communications platform. Challenges and in-memory rate limits are process-local and reset on restart; run a single instance for now. There is no multi-factor authentication, account recovery, end-to-end messaging, VPN, or independent security audit. Revoke access to a lost device by revoking its device record. Use HTTPS only, protect the database URL, and do not expose private keys.


## AEGIS Sentinel v0.5
- `GET /v1/security/events` — authenticated device session required; returns up to 100 recent events for the same AEGIS identity.
- Records rejected authentication/registration proofs, denied authentication for unknown or revoked devices, successful device authentication, and device revocation.
- Event records include server-observed remote IP, a shortened user-agent string, timestamp, event type and limited non-secret details. They never store bearer tokens, private keys, passwords or message contents.
- IP addresses may represent shared carrier, school, workplace or household gateways; they do not identify a person or exact location. No automatic IP blocking is performed.
- Events are retained in PostgreSQL until manually managed; this release does not yet implement automatic retention expiry. Restrict database access and configure an appropriate retention policy before production use.
- Sentinel revokes device sessions; it does not shut down the phone or backend process.


### v0.5.1 Sentinel event coverage
Device registration and reconnection now create a `device_registered_or_reconnected` event associated with the registered AEGIS identity. This ensures a newly connected device can produce a visible Sentinel event without requiring a failed-login test. Existing identity keys and device records are unchanged.
