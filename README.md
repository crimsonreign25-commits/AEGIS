# AEGIS v0.1 — Local identity + PWA foundation

**ONE NETWORK. GLOBAL ACCESS. PRIVATE BY DESIGN.**

This is a working, dependency-free web PWA foundation. It is intentionally not presented as a finished global communications service.

## What works in v0.1
- Responsive cybersecurity-inspired dashboard for mobile and desktop.
- Installable PWA manifest and service worker that caches the application shell for offline launch after the first successful visit.
- First-launch anonymous identity generation in the browser using the Web Crypto API.
- ECDSA P-256 signing key pair and ECDH P-256 key-agreement pair.
- Private keys are generated with `extractable: false` and stored as structured-cloned `CryptoKey` objects in IndexedDB.
- Public identity code is a short SHA-256 fingerprint of the signing public key. It is an identifier, never a password.
- Optional display name, identity-code copy, and local security status views.
- No third-party JavaScript libraries, analytics SDK, or telemetry.

## Security limits
- This uses browser-managed local storage, not Android hardware-backed Keystore. Non-extractable Web Crypto keys are not a defence against a compromised browser runtime, malicious same-origin script, compromised operating system, or device owner with full control.
- Clearing browser data, losing the browser profile, or losing the device can destroy this identity. No recovery flow exists yet. Do not use it as the sole identity for important communications.
- The app currently has no backend, account/device recovery, trusted-device linking, messaging, group chat, voice/video calls, VPN tunnel, DNS/IPv6 protection, remote sessions, or APK. The UI explicitly marks these as not active/planned.
- A production service must authenticate with cryptographic challenge-response proof of possession and enforce all permissions on the backend. The public identity code must never be treated as a credential.
- The first PWA install/offline cache requires a successful initial online visit. Service workers require HTTPS, except on localhost.

## Requirements
Node.js 20+ is recommended. No npm packages are required.

## Run
```bash
npm run dev
```
Open `http://localhost:4173`.

## Test and build
```bash
npm test
npm run build
npm run preview
```
The production-ready static site is generated in `dist/`.

## Deploy
Upload the contents of `dist/` to a static host with HTTPS. Configure SPA fallback to `/index.html` if the host requires it. GitHub Pages, Cloudflare Pages, Netlify, or Render static sites can serve this app.

## Android
The PWA can be installed from a supported Android browser. A downloadable APK is **not** included in v0.1. Before packaging a native Android app, add Capacitor and move key custody to Android Keystore-backed storage, then test on physical devices and sign the release APK.

## Next milestone
Implement a Node.js/TypeScript backend with device registration, signed challenge-response, revocation, rate limits, audit logging that avoids message content, and a reviewed recovery design. Integrate a maintained, audited E2EE protocol implementation; do not invent a protocol.
