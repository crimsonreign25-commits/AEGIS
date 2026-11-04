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


## AEGIS v0.5.6 Sentinel verification update

This complete repository package includes the Sentinel frontend, service-worker cache refresh, backend v0.5.3, and backend event-attribution update. Rejected authentication or registration proofs are attached to an identity only when the submitted public key already exists in the device registry; unknown keys are not assigned to an identity. The authenticated events endpoint returns only events for the identity associated with the valid bearer session. Device revocation marks the device revoked and deletes its sessions.

Automated checks cover the PWA shell, local key operations, signature verification/rejection, known-device attribution contract, and authenticated-identity guard contract. The backend requires PostgreSQL and live HTTP/database integration tests must still be performed on a separate test database before any security audit or production-readiness claim. No automatic security-event expiry policy is included.

## AEGIS v0.6.0 — Core security hardening

This release builds on the deployed v0.5.6 frontend / v0.5.3 backend baseline. It preserves the IndexedDB database name, object store, identity record key, and existing non-extractable CryptoKey objects.

### Changes
- **Revocation is now persistent:** a device whose public key is already marked revoked cannot silently clear `revoked_at` by calling registration again. The backend returns HTTP 403 and records `registration_blocked_revoked_device`.
- **Challenge storage is bounded:** expired challenges are cleaned when new challenges are created, and the in-memory challenge map has a maximum size.
- **PWA cache version advanced** to force clients to load the updated application shell.
- Backend health reports version `0.6.0`.

### Deploy
- Static site: repository root; Build Command `npm run build`; Publish Directory `dist`.
- Backend web service: Root Directory `backend`; Build Command `npm install`; Start Command `npm start`.
- Keep the existing PostgreSQL database and environment variables. Do not replace `DATABASE_URL` or create a new database for this update.

### Current capability status
**Implemented in this package:** local P-256 identity generation, local IndexedDB key storage, challenge-response device registration/authentication, hashed bearer-session storage, device listing/revocation, authenticated identity-scoped Sentinel events, conservative source-IP reporting, PWA shell, and bounded in-memory challenge storage.

**Not implemented / not production-ready:** VPN tunnelling, DNS protection, end-to-end encrypted chat, group rooms, voice/video calling, secure file sharing, native Android APK, account recovery, multi-factor authentication, durable distributed rate limiting, automatic event retention, and independent security audit. The ECDH key is generated locally but this release does not yet implement a complete audited messaging/key-agreement protocol. Do not treat the current app as a complete private network or use it to protect high-risk communications.

### Verification
Run `npm test`, `npm run build`, and `npm run test:backend` from the repository root. Backend integration tests against PostgreSQL and a staging deployment are still required before production security sign-off. The test suite does not claim an independent security audit.

## AEGIS v0.7.0 — Integrated workspace foundation

This release adds a unified mobile-first workspace navigation for Messenger, Rooms, Audio & Video Masking, Vault, VPN & DNS, and Workhub while preserving the existing identity database and Sentinel/device backend.

### What is usable now
- Existing local P-256 identity and device trust foundation remains in place.
- Existing device registration, device listing/revocation, and Sentinel event view remain available.
- New module navigation and status pages make the intended product structure visible.
- Media Masking includes an explicit local camera preview with local-only blur/monochrome preview filters. The preview stops when the user presses Stop camera.

### Important boundaries
The new Messenger, Rooms, Vault file store, VPN tunnel, Workhub sync, and calling pipeline are **not yet implemented as live services**. Their pages explicitly state this. The camera preview filters do not alter a remote call stream. Audio voice profiles are settings placeholders and do not access or transform microphone audio. A real VPN needs a native Android `VpnService` app and operated VPN servers; a browser PWA cannot provide device-wide VPN protection. End-to-end messaging requires reviewed peer-key verification, a complete protocol, secure transport, replay protection, and integration tests. Do not use this release as a substitute for an audited secure communications product.

### Deployment
Keep the existing Render services, PostgreSQL database, `DATABASE_URL`, `NODE_ENV`, and `ALLOWED_ORIGIN`. Deploy the frontend from repository root with `npm run build` and publish `dist`. Deploy the backend from `backend/` with `npm install` and `npm start`. Do not create a replacement database or revoke your current device.

### Verification
`npm test`, `npm run build`, and `npm run test:backend` pass in the build environment. No live PostgreSQL integration test or Render deployment was performed for this package.

# AEGIS v0.8.0-alpha1 — Native Android foundation

This package adds the first native Android application source under `android/` while retaining the existing web app, Node backend, database schema, and browser identity storage.

## Android foundation included
- Native Kotlin + Jetpack Compose application shell.
- P-256 signing key generated in Android Keystore; private key is not exported.
- Public-key challenge and registration against the existing `/v1/challenges` and `/v1/devices/register` endpoints.
- DER ECDSA signatures converted to the 64-byte IEEE-P1363 format expected by the existing Node backend.
- Returned bearer session encrypted with an AES-GCM key held by Android Keystore before local storage.
- GitHub Actions workflow to build a debug APK and publish it as a workflow artifact.

The Android app registers as a **new device** under the existing backend's current public-key/fingerprint model. It does not clone, import, or replace the browser's non-extractable private key. This is deliberate: safe cross-device identity recovery and authorization need a separately designed approval protocol.

## Build the Android APK
A GitHub Actions workflow is included at `.github/workflows/android-apk.yml`. Push the repository, open GitHub Actions, run **Build AEGIS Android APK**, and download the `aegis-android-debug-apk` artifact after a successful run. The debug APK is for development/testing, not a signed production release.

Local build prerequisites: JDK 17 and Gradle 8.9. Run `gradle :android:app:assembleDebug` from the repository root.

## Current completion status — read before use
This is a real native identity/enrolment milestone, **not the finished AEGIS platform**. The Android source has not been compiled in this environment because Gradle/Android SDK are unavailable here. The GitHub Actions build is provided to perform that compilation. The following are still not implemented as live, tested services: encrypted one-to-one/group messaging and key rotation; real-time calling/signaling; outgoing audio transformation; outgoing video processing; encrypted Vault file storage/sharing; Workhub sync; and a WireGuard-compatible Android VPN client plus operated VPN server nodes. The UI must not claim these are active. No VPN tunnel is currently provided.

The existing v0.7 frontend and backend tests were run successfully before packaging. They are not a security audit and do not verify Android compilation, live PostgreSQL behaviour, or production deployment. Do not use this alpha for high-risk communications. Do not revoke the current browser device while testing.

## Existing deployment preservation
Keep the current Render services, PostgreSQL database, `DATABASE_URL`, `NODE_ENV`, and `ALLOWED_ORIGIN`. Do not create a replacement database, reset tables, or overwrite the existing identity. The Android app's default backend URL is the existing AEGIS backend URL and can be edited on its enrolment screen.


## Conversation retention preferences (alpha2)

The Messenger and Rooms pages now include retention preference controls: delete your local conversation copy when you leave, or keep it for 1, 7, 30, 90, or 180 days. Preferences are saved locally per category. **Automatic deletion is not yet enforced** because the live messaging/room transport and server-side retention worker are not implemented in this alpha. The setting applies to the user's copy only; it cannot erase other members' copies or backups. A future room-wide policy must be agreed by members and enforced by the live service.

## v0.8.1 development milestone — backend retention primitives
This build adds additive PostgreSQL tables and authenticated API primitives for per-identity chat/room retention policies, ciphertext-only item storage, delete-on-leave requests, and scheduled expiry cleanup. The existing browser preferences remain local and are not yet connected to these endpoints. This does not complete Messenger or Rooms: end-to-end encryption, key exchange, membership/authorization, client integration, and live database integration tests are still required. The Android VPN, real-time calls, outgoing media masking, Vault and Workhub remain unfinished.

## v0.9.0 development milestone — local encrypted Vault and Workhub

This milestone adds functional, device-local encrypted storage to the PWA:

- Vault files up to 20 MB are encrypted in the browser with AES-256-GCM before being written to a separate IndexedDB database. File contents and metadata are encrypted. Download decrypts the selected file in memory; delete removes the encrypted local record.
- Workhub notes and tasks are encrypted with the same identity-bound local key. Tasks can be marked complete/reopened and deleted.
- The AES key is derived with ECDH + HKDF from the existing non-extractable local identity agreement key. The derived AES key is also non-extractable. Random 96-bit GCM IVs are generated for every encryption operation; authentication-tag verification rejects modified ciphertext.
- The new `vault-store.mjs` module is included in the production build and service-worker precache.

**Storage boundary:** these Vault and Workhub records are local to this browser profile. They are not synchronized to the backend, other devices, or room members. Clearing site storage, losing the original identity key, or losing the browser profile can make them unrecoverable. This is local encryption-at-rest functionality, not an independently audited secure vault and not a substitute for a separate backup/recovery design. The 20 MB limit is enforced before encryption.

### Verification
The root test suite checks identity-bound non-extractable AES key derivation, AES-GCM record round trips, binary file encryption/decryption, and tamper rejection. `npm test`, `npm run build`, and `npm run test:backend` pass in the local build environment. Android compilation and live PostgreSQL/Render integration are not verified here.

## Secure file-share cryptography module (v0.9.1 development addition)

`secure-share.mjs` implements an encrypted portable share-package primitive:
- A random per-file AES-256-GCM key encrypts file bytes.
- The file key is wrapped using a code-derived AES-256-GCM key (PBKDF2-HMAC-SHA-256, 310,000 iterations, random 128-bit salt).
- Authenticated metadata binds the filename, MIME type, size, allowed recipient mode and expiry to the ciphertext.
- A recipient can choose protected viewing or secure download when both are allowed; sender restrictions are enforced by the decrypt function.
- Wrong codes and modified packages are rejected.

This is a cryptographic module and test, not yet a deployed Messenger/Rooms file-transfer service. Package exchange, server-side expiry enforcement, download-count enforcement, revocation, key delivery, UI integration and multi-device synchronization remain unimplemented. Browser-only protected viewing cannot prevent screenshots or copying after decryption. PBKDF2 is used because Web Crypto does not provide Argon2id natively; a reviewed native Argon2id implementation is a future hardening item.

Run `node secure-share.test.mjs` or `npm run test:all` to exercise it.


## v0.9.2 — Secure-share workflow UI (offline package transfer)

The PWA now exposes a Secure Shares workspace. A sender chooses a file, creates a security code, selects whether the recipient may view, download, or choose either, then exports an encrypted `.aegis` package. The recipient imports that package, enters the code, and chooses protected viewing or secure download when permitted by the sender.

The recipient's view/download choice is enforced by the client cryptographic module. Protected preview currently supports images, PDFs and text; other file types require secure download. The sender should communicate the code separately from the package. The package is a bearer object: anyone with both the package and code can decrypt it. There is no hosted sharing link, server-side expiry enforcement, download count, or revocation in this offline workflow. Protected viewing cannot prevent screenshots or copying after content is displayed.

The package uses Web Crypto PBKDF2-HMAC-SHA-256 (310,000 iterations) to derive a wrapping key because browser Web Crypto does not natively expose Argon2id. This is not a claim of Argon2id use or an independent cryptographic audit.

Verification adds static UI-wiring checks to the existing encryption tests. Run `npm run test:all`.


## v0.9.3 — Authenticated ciphertext mailbox relay (backend foundation)

Added authenticated mailbox endpoints for encrypted-message transport: `POST /v1/messages` accepts a recipient AEGIS identity code and base64 ciphertext; `GET /v1/messages` returns only the authenticated device identity's mailbox; `DELETE /v1/messages/:id` deletes only a message addressed to that identity. Mailbox rows expire after 30 days and expired rows are cleaned during retrieval. The database change is additive (`CREATE TABLE IF NOT EXISTS`) and does not alter existing device, session, Sentinel or retention records.

This is a ciphertext relay only. The server does not see plaintext, but this endpoint does not implement end-to-end key agreement, peer authentication of message contents, group membership, delivery acknowledgements, multi-device synchronization, or a complete Messenger UI. A production messenger must add a reviewed client-side key establishment and message-authentication protocol before treating messages as end-to-end encrypted.

Verification: backend contract tests cover authenticated route guards, recipient-only retrieval/deletion, ciphertext-only storage and the 30-day expiry contract. These are not live PostgreSQL integration tests.


## AEGIS v0.9.5 — transport hardening checkpoint

This checkpoint makes one verified backend hardening change: production PostgreSQL TLS now requires certificate verification (`rejectUnauthorized: true`) rather than accepting unverified server certificates. A regression test fails if the unsafe setting is reintroduced. Package versions are updated to 0.9.5.

This does **not** complete or certify AEGIS. The existing product remains a development foundation. Live end-to-end Messenger/Rooms, a reviewed ratcheting protocol, full peer-key verification, production VPN, calling, outgoing media masking, Android release signing, live PostgreSQL/Render integration tests, and independent security assessment remain outstanding. Do not use this build for high-risk communications or describe it as military/government approved.

Before deploying, confirm that the PostgreSQL provider's certificate chain is trusted by the Node.js runtime. If the database uses a private CA, configure that CA explicitly rather than disabling certificate verification. A deployment may fail closed until the correct CA trust is configured; that is intentional.
