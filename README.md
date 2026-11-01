# AEGIS v0.2 — PWA + backend foundation

The root directory remains the existing v0.1 PWA. The new `backend/` directory adds a separate Node.js API for public-key device registration, proof-of-possession authentication, device listing and revocation.

## Existing PWA
- `npm install`
- `npm test`
- `npm run build`
- `npm run dev`

Deploy the root as a Render **Static Site** with build command `npm run build` and publish directory `dist`.

## New backend
See [`backend/README.md`](backend/README.md). Deploy as a separate Render **Web Service** with root directory `backend`, build command `npm install`, and start command `npm start`. It requires a Render PostgreSQL database and environment variables.

## Important
The existing PWA identity and local private keys are preserved. This milestone supplies a separate backend API; the current PWA interface does not yet include backend connection/device-management screens. The backend must be deployed and tested separately. This is not yet a complete secure communications platform.
