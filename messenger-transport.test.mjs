import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { sendEncryptedMailboxMessage, receiveEncryptedMailboxMessages } from './messenger-transport.mjs';
import { exportMessagingPublicKeys } from './message-crypto.mjs';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

async function makeIdentity() {
  const signing = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign','verify']);
  const agreement = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', signing.publicKey));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  const hex = [...digest.slice(0,10)].map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();
  const groups = hex.match(/.{1,4}/g).join('-');
  return { identityCode:`AEGIS-${groups}`, signingPublicKey:signing.publicKey, signingPrivateKey:signing.privateKey, agreementPublicKey:agreement.publicKey, agreementPrivateKey:agreement.privateKey };
}
const alice = await makeIdentity(), bob = await makeIdentity();
const aliceBundle = await exportMessagingPublicKeys(alice), bobBundle = await exportMessagingPublicKeys(bob);
const mailbox = [];
let serverId = 0;
const token = 'test-session-token-that-is-long-enough';
const fakeFetch = async (url, options = {}) => {
  const path = new URL(url).pathname;
  const method = options.method || 'GET';
  const auth = options.headers?.authorization;
  if (auth !== `Bearer ${token}`) return new Response(JSON.stringify({error:'Authentication required'}), {status:401});
  if (path === '/v1/messages' && method === 'POST') {
    const data = JSON.parse(options.body);
    mailbox.push({message_id:`00000000-0000-4000-8000-${String(++serverId).padStart(12,'0')}`,sender_identity:alice.identityCode,recipient_identity:data.recipientIdentity,ciphertext:data.ciphertext});
    return new Response(JSON.stringify({message:{message_id:mailbox.at(-1).message_id,expires_at:'later'},storage:'ciphertext-only'}),{status:201});
  }
  if (path === '/v1/messages' && method === 'GET') return new Response(JSON.stringify({messages:mailbox.filter(x=>x.recipient_identity===bob.identityCode)}));
  const match = path.match(/^\/v1\/messages\/([^/]+)$/);
  if (match && method === 'DELETE') {
    const index = mailbox.findIndex(x=>x.message_id===decodeURIComponent(match[1]));
    if (index < 0) return new Response(JSON.stringify({error:'Message not found'}),{status:404});
    mailbox.splice(index,1); return new Response(JSON.stringify({deleted:true}));
  }
  return new Response(JSON.stringify({error:'Not found'}),{status:404});
};
const sent = await sendEncryptedMailboxMessage({baseUrl:'https://aegis.test',token,identity:alice,peerBundle:bobBundle,conversationId:'conversation_123',text:'hello AEGIS',fetchImpl:fakeFetch});
assert.ok(sent.messageId);
const seen = new Set();
const replayStore = { durable:true, async has(k){return seen.has(k);}, async add(k){seen.add(k);} };
const result = await receiveEncryptedMailboxMessages({baseUrl:'https://aegis.test',token,identity:bob,peerBundles:[aliceBundle],conversationForPeer:()=> 'conversation_123',replayStore,fetchImpl:fakeFetch});
assert.equal(result.received.length,1);
assert.equal(result.received[0].text,'hello AEGIS');
assert.equal(mailbox.length,0);
await assert.rejects(() => receiveEncryptedMailboxMessages({baseUrl:'https://aegis.test',token,identity:bob,peerBundles:[aliceBundle],conversationForPeer:()=> 'conversation_123',replayStore:{has:async()=>false,add:async()=>{}},fetchImpl:fakeFetch}), /durable replay store/);
await assert.rejects(() => sendEncryptedMailboxMessage({baseUrl:'http://example.com',token,identity:alice,peerBundle:bobBundle,conversationId:'conversation_123',text:'no',fetchImpl:fakeFetch}), /HTTPS/);
console.log('PASS: authenticated mailbox send/receive adapter, ciphertext envelope transport, signature-verified decryption, durable replay-store requirement, and delete-after-success behavior.');
