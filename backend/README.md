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


### v0.5.2 source-IP attribution
The backend no longer records its local socket/proxy address as the visitor IP. It accepts `X-Forwarded-For` only when exactly one syntactically valid IP is present; when the header is absent, invalid, or contains a multi-hop chain, the event stores `unavailable` rather than guessing. It deliberately does not trust `X-Real-IP`. This is conservative attribution, not personal identification. Verify the exact header behaviour in the deployed Render environment before treating recorded IPs as authoritative.


## Sentinel authentication-event attribution (v0.5.3)

Rejected registration/authentication proofs and denied authentication attempts are associated with an existing AEGIS identity only when the submitted public key is already present in `aegis_devices`. Unknown public keys remain unassigned; Sentinel does not guess an identity. Event records contain event type, server-observed source metadata, a limited user-agent string and non-secret reason/device metadata. Passwords, private keys, bearer tokens and message contents are not recorded.

The security-event endpoint requires a valid bearer session and returns only events for that session's identity. Revoking a device marks it revoked and deletes all sessions for that device. A revoked session is rejected by subsequent authenticated requests. The current automated tests exercise cryptographic proof and event-attribution contracts; full HTTP/database integration tests still require a dedicated test PostgreSQL database and must be run before production security sign-off.

### v0.6.0 revocation hardening
A public key already marked revoked cannot be reactivated by registering the same key again. Registration uses an `ON CONFLICT ... WHERE revoked_at IS NULL` condition and returns HTTP 403 when the existing device is revoked. This prevents the previous re-registration path from clearing the revocation marker. A proper account/device recovery workflow is not yet implemented; do not revoke the only device holding the identity until recovery is designed and tested.

Pending one-time challenges are now expired opportunistically and the in-memory challenge map is bounded. This is still process-local and is not a substitute for a shared durable challenge store in a multi-instance deployment.


## v0.7.0 frontend integration note
The frontend now exposes Messenger, Rooms, Media Masking, Vault, VPN & DNS, and Workhub module pages. Except for the local camera preview and its CSS preview filters, these pages are architecture/status surfaces only. No chat, calling, file vault, Workhub sync, or VPN service is active. Backend API remains the v0.6 security foundation with a v0.7 health version label; no new communication endpoints are exposed.

## Conversation retention service (v0.8.1 development milestone)
The backend now includes authenticated per-identity retention policy routes and ciphertext-only item storage:
- `PUT /v1/retention/policy` — `{scope:'chats'|'rooms', conversationId, mode:'leave'|'timed', days?}`
- `POST /v1/retention/items` — stores a base64 ciphertext blob against the authenticated identity and conversation reference.
- `GET /v1/retention/items?scope=chats&conversationId=...` — retrieves that identity's stored blobs.
- `POST /v1/retention/leave` — deletes that identity's items when the saved policy is `leave`.

Allowed timed durations are 1, 7, 30, 90 and 180 days. A backend cleanup task removes expired rows once per minute. Database tables are created additively at startup; existing device/session/event tables are not dropped or reset.

**Integration and security boundary:** the frontend retention controls are still local preferences and are not yet wired to these API routes. The messaging and room services are not live. The item endpoint accepts client-encrypted ciphertext but does not implement encryption, key exchange, peer authentication, room membership, multi-device synchronization, or backup deletion. Do not send plaintext to this endpoint or describe this milestone as an end-to-end encrypted messenger. Live PostgreSQL integration tests and a security review remain required.
