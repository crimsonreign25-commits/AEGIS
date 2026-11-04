import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { identityCodeForSigningKey, exportMessagingPublicKeys, encryptDirectMessage, decryptDirectMessage } from './message-crypto.mjs';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
async function makeIdentity() {
  const signing = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const agreement = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits','deriveKey']);
  return {signingPrivateKey:signing.privateKey,signingPublicKey:signing.publicKey,agreementPrivateKey:agreement.privateKey,agreementPublicKey:agreement.publicKey,identityCode:await identityCodeForSigningKey(signing.publicKey)};
}
const alice=await makeIdentity(), bob=await makeIdentity(), eve=await makeIdentity();
const alicePublic=await exportMessagingPublicKeys(alice), bobPublic=await exportMessagingPublicKeys(bob), evePublic=await exportMessagingPublicKeys(eve);
const substitutedAgreement=await exportMessagingPublicKeys(eve);
const forgedBundle={...bobPublic,agreementKey:substitutedAgreement.agreementKey};
await assert.rejects(()=>encryptDirectMessage({identity:alice,peer:forgedBundle,conversationId:'chat_forgery_123',text:'must reject'}),/Peer key bundle signature is invalid/);
const unsignedBundle={...bobPublic}; delete unsignedBundle.bundleSignature;
await assert.rejects(()=>encryptDirectMessage({identity:alice,peer:unsignedBundle,conversationId:'chat_unsigned_123',text:'must reject'}),/Peer key bundle is not signed/);
const conversationId='chat_test_12345678';
const envelope=await encryptDirectMessage({identity:alice,peer:bobPublic,conversationId,text:'Private AEGIS test message'});
const opened=await decryptDirectMessage({identity:bob,peer:alicePublic,conversationId,envelope});
assert.equal(opened.text,'Private AEGIS test message');
await assert.rejects(()=>decryptDirectMessage({identity:eve,peer:alicePublic,conversationId,envelope}),/identity or conversation binding/);
await assert.rejects(()=>decryptDirectMessage({identity:bob,peer:evePublic,conversationId,envelope}),/identity or conversation binding/);
const changed={...envelope,ciphertext:envelope.ciphertext.slice(0,-4)+'AAAA'};
await assert.rejects(()=>decryptDirectMessage({identity:bob,peer:alicePublic,conversationId,envelope:changed}),/Message signature is invalid/);
const otherConversation={...envelope,conversationId:'chat_other_123456'};
await assert.rejects(()=>decryptDirectMessage({identity:bob,peer:alicePublic,conversationId,envelope:otherConversation}),/identity or conversation binding/);
console.log('PASS: direct-message ECDH/HKDF, AES-256-GCM, sender signatures, signed public-key bundle binding, identity checks, agreement-key substitution rejection and tamper rejection.');
