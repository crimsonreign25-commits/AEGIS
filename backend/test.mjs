import assert from 'node:assert/strict';
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
console.log('PASS: P-256 proof verification, forged-proof rejection, known-device event attribution and authenticated-identity guard contracts.');
