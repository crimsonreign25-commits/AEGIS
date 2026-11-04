/**
 * AEGIS direct-message cryptographic foundation (experimental).
 * Uses the existing P-256 ECDH/ECDSA identity keys, HKDF-SHA-256 and AES-256-GCM.
 * This is NOT a ratcheting protocol and does not provide forward secrecy or
 * post-compromise security. Verify peer fingerprints out-of-band before use.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const VERSION = 1;
const subtle = () => {
  const api = globalThis.crypto?.subtle;
  if (!api) throw new Error('Web Crypto is unavailable. Use HTTPS or a supported secure context.');
  return api;
};
const random = n => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; };
const toB64 = bytes => {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let s=''; for (const b of bytes) s+=String.fromCharCode(b); return btoa(s);
};
const fromB64 = value => {
  if (typeof value !== 'string' || value.length > 200000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Invalid base64 field.');
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value,'base64'));
  return Uint8Array.from(atob(value), c=>c.charCodeAt(0));
};
const canonical = value => encoder.encode(JSON.stringify(value));
const hex = bytes => [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();

export async function identityCodeForSigningKey(signingPublicKey) {
  const raw = new Uint8Array(await subtle().exportKey('raw', signingPublicKey));
  const digest = new Uint8Array(await subtle().digest('SHA-256', raw));
  const groups = hex(digest.slice(0,10)).match(/.{1,4}/g).join('-');
  return `AEGIS-${groups}`;
}

export async function exportMessagingPublicKeys(identity) {
  if (!identity?.signingPublicKey || !identity?.agreementPublicKey) throw new Error('Identity public keys are missing.');
  const [signing, agreement] = await Promise.all([
    subtle().exportKey('raw', identity.signingPublicKey),
    subtle().exportKey('raw', identity.agreementPublicKey)
  ]);
  const bundle = {
    identityCode: identity.identityCode,
    signingKey: toB64(new Uint8Array(signing)),
    agreementKey: toB64(new Uint8Array(agreement)),
    algorithm: 'P-256',
    version: VERSION
  };
  if (!identity.signingPrivateKey) throw new Error('Local signing private key is unavailable.');
  const signature = await subtle().sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    identity.signingPrivateKey,
    canonical(bundle)
  );
  return { ...bundle, bundleSignature: toB64(new Uint8Array(signature)) };
}

async function importPeerKeys(peer) {
  if (!peer || peer.version !== VERSION || peer.algorithm !== 'P-256' || typeof peer.identityCode !== 'string') throw new Error('Unsupported peer key bundle.');
  const signingPublicKey = await subtle().importKey('raw', fromB64(peer.signingKey), {name:'ECDSA',namedCurve:'P-256'}, true, ['verify']);
  const agreementPublicKey = await subtle().importKey('raw', fromB64(peer.agreementKey), {name:'ECDH',namedCurve:'P-256'}, true, []);
  const calculated = await identityCodeForSigningKey(signingPublicKey);
  if (calculated !== peer.identityCode) throw new Error('Peer identity code does not match its signing key.');
  if (typeof peer.bundleSignature !== 'string') throw new Error('Peer key bundle is not signed.');
  const { bundleSignature, ...bundle } = peer;
  const bundleValid = await subtle().verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPublicKey,
    fromB64(bundleSignature),
    canonical(bundle)
  );
  if (!bundleValid) throw new Error('Peer key bundle signature is invalid.');
  return { signingPublicKey, agreementPublicKey };
}

function validateContext(identity, peer, conversationId) {
  if (!identity?.identityCode || !identity.signingPrivateKey || !identity.agreementPrivateKey) throw new Error('Local identity private keys are unavailable.');
  if (!peer?.identityCode || peer.identityCode === identity.identityCode) throw new Error('A distinct peer identity is required.');
  if (typeof conversationId !== 'string' || !/^[A-Za-z0-9_-]{8,80}$/.test(conversationId)) throw new Error('Conversation ID must be 8–80 safe characters.');
}

async function deriveMessageKey(identity, peerAgreementKey, salt, sender, recipient, conversationId) {
  const shared = await subtle().deriveBits({name:'ECDH',public:peerAgreementKey}, identity.agreementPrivateKey, 256);
  const material = await subtle().importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const info = encoder.encode(`AEGIS-DIRECT-MESSAGE-V${VERSION}|${conversationId}|${sender}|${recipient}`);
  return subtle().deriveKey({name:'HKDF',hash:'SHA-256',salt,info},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}

export async function encryptDirectMessage({identity, peer, conversationId, text}) {
  validateContext(identity, peer, conversationId);
  if (typeof text !== 'string' || text.length < 1 || text.length > 10000) throw new Error('Message must contain 1–10,000 characters.');
  const peerKeys = await importPeerKeys(peer);
  const salt = random(32), iv = random(12);
  const key = await deriveMessageKey(identity, peerKeys.agreementPublicKey, salt, identity.identityCode, peer.identityCode, conversationId);
  const header = {
    format:'AEGIS-DIRECT-MESSAGE', version:VERSION,
    senderIdentity:identity.identityCode, recipientIdentity:peer.identityCode,
    conversationId, messageId:toB64(random(16)),
    createdAt:new Date().toISOString(), salt:toB64(salt), iv:toB64(iv)
  };
  const ciphertext = await subtle().encrypt({name:'AES-GCM',iv,additionalData:canonical(header),tagLength:128},key,encoder.encode(text));
  const signed = {...header,ciphertext:toB64(new Uint8Array(ciphertext))};
  const signature = await subtle().sign({name:'ECDSA',hash:'SHA-256'},identity.signingPrivateKey,canonical(signed));
  return {...signed,signature:toB64(new Uint8Array(signature))};
}

export async function decryptDirectMessage({identity, peer, conversationId, envelope}) {
  validateContext(identity, peer, conversationId);
  if (!envelope || envelope.format!=='AEGIS-DIRECT-MESSAGE' || envelope.version!==VERSION) throw new Error('Unsupported message envelope.');
  if (envelope.senderIdentity!==peer.identityCode || envelope.recipientIdentity!==identity.identityCode || envelope.conversationId!==conversationId) throw new Error('Message identity or conversation binding does not match.');
  const peerKeys = await importPeerKeys(peer);
  const {signature,...signed} = envelope;
  const valid = await subtle().verify({name:'ECDSA',hash:'SHA-256'},peerKeys.signingPublicKey,fromB64(signature),canonical(signed));
  if (!valid) throw new Error('Message signature is invalid.');
  const salt=fromB64(envelope.salt), iv=fromB64(envelope.iv), ciphertext=fromB64(envelope.ciphertext);
  if (salt.length!==32 || iv.length!==12 || ciphertext.length<16 || ciphertext.length>20000) throw new Error('Message cryptographic fields are invalid.');
  const header = {
    format:envelope.format,version:envelope.version,senderIdentity:envelope.senderIdentity,
    recipientIdentity:envelope.recipientIdentity,conversationId:envelope.conversationId,
    messageId:envelope.messageId,createdAt:envelope.createdAt,salt:envelope.salt,iv:envelope.iv
  };
  const key = await deriveMessageKey(identity,peerKeys.agreementPublicKey,salt,peer.identityCode,identity.identityCode,conversationId);
  try {
    const plaintext = await subtle().decrypt({name:'AES-GCM',iv,additionalData:canonical(header),tagLength:128},key,ciphertext);
    return {text:decoder.decode(plaintext),senderIdentity:peer.identityCode,messageId:envelope.messageId,createdAt:envelope.createdAt};
  } catch { throw new Error('Message authentication failed. The message may have been altered or addressed to another key.'); }
}
