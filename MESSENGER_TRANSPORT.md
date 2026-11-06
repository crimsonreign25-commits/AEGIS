# AEGIS Messenger transport adapter — experimental

This milestone connects the v0.9.6 signed message envelope to the authenticated ciphertext mailbox API.

## What it does
- `sendEncryptedMailboxMessage()` encrypts/signs locally using the existing experimental envelope and posts only its serialized base64 representation to `/v1/messages`.
- `receiveEncryptedMailboxMessages()` fetches the authenticated inbox, accepts only senders whose signed public-key bundles are already supplied by the caller, verifies/decrypts each envelope, records a replay identifier through a durable store, and only then deletes the server mailbox item.
- The receiver refuses to operate without a durable replay store (`{ durable: true, has(key), add(key) }`). A future app integration must implement this using durable device-local storage such as IndexedDB and test crash/restart behavior.

## Important limitations
This adapter does not implement peer discovery or key transparency. Peer bundles must be obtained and verified out-of-band. The underlying static P-256 ECDH design is experimental and does not provide Double Ratchet, forward secrecy, or post-compromise security. It is not suitable for sensitive or production communications. A reviewed protocol and independent security review are still required.

## Local tests
Run `npm test`, `npm run build`, and `npm run test:backend` from the project root. The transport test uses a mocked mailbox API; it does not prove the live Render backend works between two real devices.
