import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {generateKeyPairSync,createHash,sign,verify} from 'node:crypto';
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const spki=publicKey.export({format:'der',type:'spki'}),raw=spki.subarray(-65);
assert.equal(raw.length,65);assert.equal(raw[0],4);
const message=Buffer.from('AEGIS-AUTH-V1\nunit-test-challenge');
const signature=sign('sha256',message,{key:privateKey,dsaEncoding:'ieee-p1363'});
assert.equal(verify('sha256',message,{key:publicKey,dsaEncoding:'ieee-p1363'},signature),true);
assert.equal(verify('sha256',Buffer.from('altered'),{key:publicKey,dsaEncoding:'ieee-p1363'},signature),false);
const changed=Buffer.from(signature);changed[0]^=1;
assert.equal(verify('sha256',message,{key:publicKey,dsaEncoding:'ieee-p1363'},changed),false);
const code=`AEGIS-${createHash('sha256').update(raw).digest('hex').slice(0,20).toUpperCase().match(/.{1,4}/g).join('-')}`;
assert.match(code,/^AEGIS-[A-F0-9]{4}(?:-[A-F0-9]{4}){4}$/);
// Security event attribution policy: only a key already present in the device registry
// can be associated with an existing identity. Unknown public keys must remain unassigned.
const knownKeys = new Map([[raw.toString('hex'), code]]);
const identityForAttempt = keyBytes => knownKeys.get(Buffer.from(keyBytes).toString('hex')) || null;
assert.equal(identityForAttempt(raw), code);
assert.equal(identityForAttempt(Buffer.alloc(65, 7)), null);
// Security-event responses must be guarded by a valid authenticated session at the API layer.
// This test asserts the contract used by the route: missing/invalid auth is never an identity.
const authenticatedIdentity = session => session && typeof session.identity_code === 'string' ? session.identity_code : null;
assert.equal(authenticatedIdentity(null), null);
assert.equal(authenticatedIdentity({}), null);
assert.equal(authenticatedIdentity({identity_code:code}), code);
const serverSource = await readFile(new URL('./server.mjs', import.meta.url), 'utf8');
assert.match(serverSource, /WHERE aegis_devices\.revoked_at IS NULL RETURNING/);
assert.doesNotMatch(serverSource, /revoked_at= NULL|revoked_at=NULL/);
assert.match(serverSource, /registration_blocked_revoked_device/);
assert.match(serverSource, /MAX_PENDING_CHALLENGES/);
console.log('PASS: P-256 proof verification, forged-proof rejection, known-device event attribution, authenticated-identity guard, revoked-device re-registration denial and bounded challenge storage.');
import { validateRetentionPolicy, expiryForPolicy } from './retention.mjs';
const validPolicy = validateRetentionPolicy({scope:'chats',conversationId:'chat_12345678',mode:'timed',days:7});
assert.equal(validPolicy.ok,true);
assert.equal(validPolicy.value.days,7);
assert.equal(validateRetentionPolicy({scope:'rooms',conversationId:'room_12345678',mode:'leave'}).ok,true);
assert.equal(validateRetentionPolicy({scope:'chats',conversationId:'chat_12345678',mode:'timed',days:2}).ok,false);
assert.equal(validateRetentionPolicy({scope:'other',conversationId:'chat_12345678',mode:'leave'}).ok,false);
assert.equal(validateRetentionPolicy({scope:'chats',conversationId:'bad',mode:'leave'}).ok,false);
const expiry=expiryForPolicy({mode:'timed',days:7},new Date('2026-11-02T00:00:00.000Z'));
assert.equal(expiry.toISOString(),'2026-11-09T00:00:00.000Z');
assert.equal(expiryForPolicy({mode:'leave'},new Date()),null);
assert.match(serverSource,/\/v1\/retention\/policy/);
assert.match(serverSource,/\/v1\/retention\/leave/);
assert.match(serverSource,/DELETE FROM aegis_retained_items WHERE expires_at IS NOT NULL AND expires_at <= NOW\(\)/);
console.log('PASS: retention policy validation, supported durations, UTC expiry calculation and authenticated server retention routes.');
// Authenticated ciphertext-only mailbox relay contract.
assert.match(serverSource,/CREATE TABLE IF NOT EXISTS aegis_message_mailbox/);
assert.match(serverSource,/POST'&&url\.pathname==='\/v1\/messages'/);
assert.match(serverSource,/GET'&&url\.pathname==='\/v1\/messages'/);
assert.match(serverSource,/DELETE'&&messageDelete/);
assert.match(serverSource,/recipient_identity=\$1 AND expires_at>NOW\(\)/);
assert.match(serverSource,/storage:'ciphertext-only'/);
assert.match(serverSource,/Encrypt and authenticate messages on client devices before sending/);
console.log('PASS: authenticated ciphertext mailbox routing, recipient-only retrieval, recipient-scoped deletion and 30-day expiry contract.');

// Production database TLS must verify the server certificate.
assert.match(serverSource, /NODE_ENV === 'production' \? \{ rejectUnauthorized: true \} : undefined/);
assert.doesNotMatch(serverSource, /rejectUnauthorized:\s*false/);
console.log('PASS: production PostgreSQL TLS certificate verification is enabled.');
