/**
 * AEGIS authenticated mailbox transport adapter.
 * Experimental integration of the v0.9.6 message envelope with the existing
 * authenticated ciphertext mailbox. This is not a production E2EE protocol:
 * it has no ratchet/forward secrecy, key transparency, prekeys, or multi-device
 * session lifecycle. Peer bundles must be verified out-of-band.
 */
import { encryptDirectMessage, decryptDirectMessage } from './message-crypto.mjs';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_ENVELOPE_BYTES = 8500; // stay below backend's 12,000-char base64 limit

function toBase64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function fromBase64(value) {
  if (typeof value !== 'string' || value.length > 12000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid mailbox payload.');
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value, 'base64'));
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
function endpoint(baseUrl, path) { return `${String(baseUrl).replace(/\/$/, '')}${path}`; }
async function request(url, token, options = {}, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== 'function') throw new Error('Fetch is unavailable.');
  const response = await fetchImpl(url, {
    ...options,
    headers: { authorization: `Bearer ${token}`, ...(options.body ? { 'content-type': 'application/json' } : {}), ...options.headers }
  });
  let body; try { body = await response.json(); } catch { body = {}; }
  if (!response.ok) throw new Error(body.error || `Mailbox request failed (${response.status}).`);
  return body;
}
function validateSession({ baseUrl, token, identity }) {
  if (!/^https:\/\//i.test(baseUrl || '') && !/^http:\/\/localhost(?::\d+)?$/i.test(baseUrl || '')) throw new Error('Use HTTPS for the AEGIS backend.');
  if (typeof token !== 'string' || token.length < 20) throw new Error('An authenticated AEGIS session is required.');
  if (!identity?.identityCode) throw new Error('Local AEGIS identity is required.');
}

/**
 * Store contract: has(key), add(key). Use durable per-device storage in the app.
 * This module deliberately refuses to silently use volatile memory for replay
 * tracking, because a page reload would otherwise forget accepted message IDs.
 */
export async function sendEncryptedMailboxMessage({ baseUrl, token, identity, peerBundle, conversationId, text, fetchImpl }) {
  validateSession({ baseUrl, token, identity });
  const envelope = await encryptDirectMessage({ identity, peer: peerBundle, conversationId, text });
  const serialized = encoder.encode(JSON.stringify(envelope));
  if (serialized.length > MAX_ENVELOPE_BYTES) throw new Error('Encrypted message is too large for the mailbox.');
  const ciphertext = toBase64(serialized);
  const result = await request(endpoint(baseUrl, '/v1/messages'), token, {
    method: 'POST', body: JSON.stringify({ recipientIdentity: peerBundle.identityCode, ciphertext })
  }, fetchImpl);
  return { messageId: result.message?.message_id, recipientIdentity: peerBundle.identityCode, storage: result.storage, expiresAt: result.message?.expires_at };
}

/**
 * Decrypt messages from the authenticated inbox. A message is deleted from the
 * server only after signature verification, decryption, and durable replay-ID
 * recording succeed. Failed/unknown messages remain for investigation/retry.
 */
export async function receiveEncryptedMailboxMessages({ baseUrl, token, identity, peerBundles, conversationForPeer, replayStore, fetchImpl }) {
  validateSession({ baseUrl, token, identity });
  if (!replayStore || typeof replayStore.has !== 'function' || typeof replayStore.add !== 'function' || replayStore.durable !== true) {
    throw new Error('A durable replay store is required before receiving messages.');
  }
  if (!Array.isArray(peerBundles)) throw new Error('Verified peer bundles are required.');
  const peers = new Map(peerBundles.map(peer => [peer.identityCode, peer]));
  const inbox = await request(endpoint(baseUrl, '/v1/messages'), token, {}, fetchImpl);
  const received = [], rejected = [];
  for (const item of (Array.isArray(inbox.messages) ? inbox.messages : [])) {
    try {
      const peer = peers.get(item.sender_identity);
      if (!peer) throw new Error('Sender is not in the locally verified peer list.');
      const raw = fromBase64(item.ciphertext);
      if (raw.length > MAX_ENVELOPE_BYTES) throw new Error('Message envelope exceeds size limit.');
      const envelope = JSON.parse(decoder.decode(raw));
      const conversationId = conversationForPeer(item.sender_identity, envelope);
      const expected = `${item.sender_identity}|${conversationId}|${envelope.messageId}`;
      if (await replayStore.has(expected)) {
        await request(endpoint(baseUrl, `/v1/messages/${encodeURIComponent(item.message_id)}`), token, { method: 'DELETE' }, fetchImpl);
        rejected.push({ messageId: item.message_id, reason: 'replay' });
        continue;
      }
      const message = await decryptDirectMessage({ identity, peer, conversationId, envelope });
      await replayStore.add(expected); // durable write must complete before server deletion
      await request(endpoint(baseUrl, `/v1/messages/${encodeURIComponent(item.message_id)}`), token, { method: 'DELETE' }, fetchImpl);
      received.push({ ...message, mailboxMessageId: item.message_id });
    } catch (error) {
      rejected.push({ messageId: item.message_id, reason: error?.message || 'Message rejected' });
    }
  }
  return { received, rejected };
}
