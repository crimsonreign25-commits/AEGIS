# AEGIS v0.9.3 development status

This is a development build, not AEGIS 1.0 and not a security-audited release.

## Implemented and tested in this source package
- Browser P-256 signing/ECDH identity generation and non-extractable key storage.
- Existing backend challenge-response device enrolment, hashed sessions, device listing/revocation, and identity-scoped Sentinel event routes.
- Local Vault file encryption/decryption using AES-256-GCM with an identity-bound non-extractable derived key. Files remain in the local browser profile; 20 MB per-file limit.
- Local encrypted Workhub notes and tasks.
- Chat/room retention preference UI and backend primitives for per-identity ciphertext-only retention records and expiry cleanup. Not connected to a live chat service.
- Secure Shares UI: sender creates an encrypted `.aegis` package, selects view-only/download-only/or recipient choice; recipient imports it, enters the code and chooses protected preview or secure download when allowed.
- Secure-share encryption uses a random AES-256-GCM file key wrapped by PBKDF2-HMAC-SHA-256 (310,000 iterations). Wrong codes and tampering are rejected.
- New authenticated ciphertext mailbox relay endpoints: send ciphertext to an existing AEGIS identity, retrieve only the authenticated recipient's mailbox, and delete only recipient-owned mailbox items. Rows expire after 30 days. Database migration is additive.
- PWA production build and offline shell.

## Explicitly not complete
- The mailbox is transport plumbing only. There is no reviewed end-to-end key agreement, authenticated message format, Messenger/Private Rooms UI integration, membership management, group key rotation, delivery/read receipts or multi-device synchronization. Do not call this production E2EE messaging yet.
- Retention is not wired to a live messaging client. It cannot delete data in a messaging service that does not yet exist.
- Secure Shares currently exchange a portable `.aegis` package offline. There are no hosted share links, server-side expiry, download counts, remote revocation, recipient-bound file-key wrapping or transfer audit log.
- Voice/video calling: no production signaling, STUN/TURN deployment or tested call flow.
- Audio/video masking: no outgoing call-stream DSP or video frame transformation pipeline. Current camera effects are local preview only.
- VPN: no active Android VpnService tunnel, WireGuard client integration, operated VPN server nodes, DNS routing or leak tests.
- Vault and Workhub are local-only, with no cross-device sync or recovery.
- Android source is included, but APK compilation has not been run in this environment.

## Verification performed
`npm run test:all` passes frontend tests, secure-share cryptographic tests, PWA production build and backend unit/contract tests.

Not performed: live PostgreSQL integration tests, Render deployment verification, Android SDK/Gradle compilation, WebRTC integration, VPN server connectivity tests, independent cryptographic/security audit, or multi-device end-to-end tests.

Keep the existing Render database and secrets. The new mailbox table is additive. Do not reset the database, replace `DATABASE_URL`, or revoke the current device during testing. Do not use this development build for high-risk communications.


## AEGIS v0.9.5 — transport hardening checkpoint

This checkpoint makes one verified backend hardening change: production PostgreSQL TLS now requires certificate verification (`rejectUnauthorized: true`) rather than accepting unverified server certificates. A regression test fails if the unsafe setting is reintroduced. Package versions are updated to 0.9.5.

This does **not** complete or certify AEGIS. The existing product remains a development foundation. Live end-to-end Messenger/Rooms, a reviewed ratcheting protocol, full peer-key verification, production VPN, calling, outgoing media masking, Android release signing, live PostgreSQL/Render integration tests, and independent security assessment remain outstanding. Do not use this build for high-risk communications or describe it as military/government approved.

Before deploying, confirm that the PostgreSQL provider's certificate chain is trusted by the Node.js runtime. If the database uses a private CA, configure that CA explicitly rather than disabling certificate verification. A deployment may fail closed until the correct CA trust is configured; that is intentional.
