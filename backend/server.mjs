import http from 'node:http';
import crypto from 'node:crypto';
import { isIP } from 'node:net';
import pg from 'pg';
import { validateRetentionPolicy, expiryForPolicy } from './retention.mjs';
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined, max: 5 });
const PORT = Number(process.env.PORT || 10000);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
const challenges = new Map();
const limits = new Map();
const MAX_BODY = 16 * 1024;
const TOKEN_TTL_DAYS = 30;
const MAX_PENDING_CHALLENGES = 5000;
const CHALLENGE_TTL_MS = 120000;
const send = (res, status, value) => { res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Access-Control-Allow-Origin': ALLOWED_ORIGIN || 'null','Vary':'Origin'}); res.end(JSON.stringify(value)); };
function cors(req,res) { const origin=req.headers.origin; if (ALLOWED_ORIGIN && origin && origin!==ALLOWED_ORIGIN) return false; if (ALLOWED_ORIGIN && origin===ALLOWED_ORIGIN) res.setHeader('Access-Control-Allow-Origin',ALLOWED_ORIGIN); res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS'); res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization'); res.setHeader('Access-Control-Max-Age','600'); return true; }
async function readBody(req) { let raw=''; for await (const chunk of req) { raw+=chunk; if (Buffer.byteLength(raw)>MAX_BODY) throw Object.assign(new Error('Request too large'),{status:413}); } try { return JSON.parse(raw||'{}'); } catch { throw Object.assign(new Error('Invalid JSON'),{status:400}); } }
const decode = value => Buffer.from(value,'base64');
const encode = value => Buffer.from(value).toString('base64');
function validPublicKey(value) { if(typeof value!=='string'||value.length>256) return false; const b=decode(value); return b.length===65&&b[0]===4&&encode(b)===value; }
function fingerprint(raw) { const h=crypto.createHash('sha256').update(raw).digest('hex').slice(0,20).toUpperCase(); return `AEGIS-${h.match(/.{1,4}/g).join('-')}`; }
function publicKeyObject(raw) { const prefix=Buffer.from('3059301306072A8648CE3D020106082A8648CE3D030107034200','hex'); return crypto.createPublicKey({key:Buffer.concat([prefix,raw]),format:'der',type:'spki'}); }
function checkSignature(raw,message,signature) { try { const sig=decode(signature); return sig.length===64&&crypto.verify('sha256',Buffer.from(message),{key:publicKeyObject(raw),dsaEncoding:'ieee-p1363'},sig); } catch { return false; } }
function newChallenge(publicKey) { const now=Date.now(); for (const [id,item] of challenges) if (item.expires < now) challenges.delete(id); if (challenges.size >= MAX_PENDING_CHALLENGES) { const oldest=challenges.keys().next().value; if (oldest) challenges.delete(oldest); } const id=crypto.randomUUID(), nonce=crypto.randomBytes(32).toString('base64url'); const message=`AEGIS-AUTH-V1\n${id}\n${nonce}\n${now}`; challenges.set(id,{publicKey,message,expires:now+CHALLENGE_TTL_MS}); return {challengeId:id,message,expiresInSeconds:120}; }
function useChallenge(id,key,signature) { const item=challenges.get(id); challenges.delete(id); if(!item||item.expires<Date.now()||item.publicKey!==key) return false; return checkSignature(decode(key),item.message,signature); }
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
async function auth(req) { const value=req.headers.authorization||''; if(!value.startsWith('Bearer ')) return null; const hash=tokenHash(value.slice(7)); const result=await pool.query(`SELECT d.device_id,d.identity_code,d.label,d.created_at,d.last_seen_at FROM aegis_sessions s JOIN aegis_devices d ON d.device_id=s.device_id WHERE s.token_hash=$1 AND s.expires_at>NOW() AND d.revoked_at IS NULL`,[hash]); if(!result.rowCount) return null; await pool.query('UPDATE aegis_devices SET last_seen_at=NOW() WHERE device_id=$1',[result.rows[0].device_id]); return result.rows[0]; }
async function issueSession(deviceId) { const token=crypto.randomBytes(32).toString('base64url'); await pool.query('INSERT INTO aegis_sessions(token_hash,device_id,expires_at) VALUES($1,$2,NOW()+($3 || \' days\')::interval)',[tokenHash(token),deviceId,String(TOKEN_TTL_DAYS)]); return token; }
function getObservedSourceIp(req) {
 // Render terminates public HTTPS before forwarding to this Node process. The
 // socket address is therefore often a loopback/proxy address, not the visitor.
 // Accept X-Forwarded-For only when it contains exactly one valid IP; if a chain
 // is present, refuse to guess which hop is the client. Never trust x-real-ip.
 const raw=String(req.headers['x-forwarded-for']||'').trim();
 if(!raw || raw.includes(',')) return 'unavailable';
 const candidate=raw.trim();
 if(!isIP(candidate) || candidate==='127.0.0.1' || candidate==='::1' || candidate==='0.0.0.0' || candidate==='::') return 'unavailable';
 return candidate.replace(/^::ffff:/,'');
}
async function recordEvent(req,type,identityCode=null,details={}) { const ip=getObservedSourceIp(req); const ua=String(req.headers['user-agent']||'').slice(0,180); await pool.query('INSERT INTO aegis_security_events(event_id,identity_code,event_type,source_ip,user_agent,details,created_at) VALUES($1,$2,$3,$4,$5,$6,NOW())',[crypto.randomUUID(),identityCode,type,ip,ua,JSON.stringify(details)]); }
async function knownIdentityForPublicKey(publicKey) { if(!validPublicKey(publicKey)) return null; const found=await pool.query('SELECT identity_code FROM aegis_devices WHERE public_key=$1 LIMIT 1',[decode(publicKey)]); return found.rows[0]?.identity_code || null; }
async function init() { if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required'); await pool.query(`CREATE TABLE IF NOT EXISTS aegis_devices(device_id UUID PRIMARY KEY,identity_code TEXT NOT NULL,public_key BYTEA NOT NULL UNIQUE,label TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),revoked_at TIMESTAMPTZ); CREATE INDEX IF NOT EXISTS aegis_devices_identity_idx ON aegis_devices(identity_code); CREATE TABLE IF NOT EXISTS aegis_sessions(token_hash TEXT PRIMARY KEY,device_id UUID NOT NULL REFERENCES aegis_devices(device_id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL); CREATE INDEX IF NOT EXISTS aegis_sessions_device_idx ON aegis_sessions(device_id); CREATE TABLE IF NOT EXISTS aegis_security_events(event_id UUID PRIMARY KEY,identity_code TEXT,event_type TEXT NOT NULL,source_ip TEXT NOT NULL,user_agent TEXT NOT NULL DEFAULT '',details JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE INDEX IF NOT EXISTS aegis_security_events_identity_time_idx ON aegis_security_events(identity_code,created_at DESC); CREATE TABLE IF NOT EXISTS aegis_retention_policies(identity_code TEXT NOT NULL,scope TEXT NOT NULL CHECK(scope IN ('chats','rooms')),conversation_id TEXT NOT NULL,mode TEXT NOT NULL CHECK(mode IN ('leave','timed')),days INTEGER,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(identity_code,scope,conversation_id),CHECK((mode='leave' AND days IS NULL) OR (mode='timed' AND days IN (1,7,30,90,180)))); CREATE TABLE IF NOT EXISTS aegis_retained_items(item_id UUID PRIMARY KEY,identity_code TEXT NOT NULL,scope TEXT NOT NULL CHECK(scope IN ('chats','rooms')),conversation_id TEXT NOT NULL,ciphertext TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),expires_at TIMESTAMPTZ); CREATE INDEX IF NOT EXISTS aegis_retained_items_expiry_idx ON aegis_retained_items(expires_at) WHERE expires_at IS NOT NULL; CREATE TABLE IF NOT EXISTS aegis_message_mailbox(message_id UUID PRIMARY KEY,sender_identity TEXT NOT NULL,recipient_identity TEXT NOT NULL,ciphertext TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW()+INTERVAL '30 days')); CREATE INDEX IF NOT EXISTS aegis_message_mailbox_recipient_idx ON aegis_message_mailbox(recipient_identity,created_at); CREATE INDEX IF NOT EXISTS aegis_message_mailbox_expiry_idx ON aegis_message_mailbox(expires_at);`); }
async function purgeExpiredItems() { await pool.query('DELETE FROM aegis_retained_items WHERE expires_at IS NOT NULL AND expires_at <= NOW()'); }
setInterval(() => purgeExpiredItems().catch(() => {}), 60000).unref();
function rateLimit(req) { const ip=req.socket.remoteAddress||'unknown',now=Date.now(),v=limits.get(ip)||{start:now,count:0}; if(now-v.start>60000){v.start=now;v.count=0;} v.count++; limits.set(ip,v); return v.count<=60; }
async function route(req,res) {
 if(!cors(req,res)) return send(res,403,{error:'Origin not allowed'});
 if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
 if(!rateLimit(req)) return send(res,429,{error:'Rate limit exceeded'});
 const url=new URL(req.url,'http://localhost');
 if(req.method==='GET'&&url.pathname==='/health'){try{await pool.query('SELECT 1');return send(res,200,{ok:true,service:'aegis-backend',version:'0.9.3',database:'connected'});}catch{return send(res,503,{ok:false,database:'unavailable'});}}
 try {
  if(req.method==='POST'&&url.pathname==='/v1/challenges'){const d=await readBody(req);if(!validPublicKey(d.publicKey))return send(res,400,{error:'Valid uncompressed P-256 public key required'});return send(res,200,newChallenge(d.publicKey));}
  if(req.method==='POST'&&url.pathname==='/v1/devices/register'){
   const d=await readBody(req);if(!validPublicKey(d.publicKey)||typeof d.challengeId!=='string'||typeof d.signature!=='string')return send(res,400,{error:'Invalid registration proof'});
   if(!useChallenge(d.challengeId,d.publicKey,d.signature)){const knownIdentity=await knownIdentityForPublicKey(d.publicKey);await recordEvent(req,'registration_proof_rejected',knownIdentity,{reason:'invalid_or_expired_proof'});return send(res,401,{error:'Challenge proof invalid, expired or already used'});}
   const raw=decode(d.publicKey),code=fingerprint(raw),label=typeof d.label==='string'?d.label.trim().slice(0,48):'';
   const result=await pool.query(`INSERT INTO aegis_devices(device_id,identity_code,public_key,label) VALUES($1,$2,$3,$4) ON CONFLICT(public_key) DO UPDATE SET last_seen_at=NOW(),label=EXCLUDED.label WHERE aegis_devices.revoked_at IS NULL RETURNING device_id,identity_code,label,created_at,last_seen_at`,[crypto.randomUUID(),code,raw,label]);
   if(!result.rowCount){await recordEvent(req,'registration_blocked_revoked_device',code,{reason:'revoked_device_cannot_self_restore'});return send(res,403,{error:'This device was revoked. It cannot restore access by registering again. Use an approved recovery process or a separately authorized device.'});}
   const token=await issueSession(result.rows[0].device_id);await recordEvent(req,'device_registered_or_reconnected',result.rows[0].identity_code,{deviceId:result.rows[0].device_id});return send(res,201,{device:result.rows[0],token,tokenExpiresInDays:TOKEN_TTL_DAYS});
  }
  if(req.method==='POST'&&url.pathname==='/v1/devices/authenticate'){
   const d=await readBody(req);if(!validPublicKey(d.publicKey)||typeof d.challengeId!=='string'||typeof d.signature!=='string')return send(res,400,{error:'Invalid authentication proof'});
   if(!useChallenge(d.challengeId,d.publicKey,d.signature)){const knownIdentity=await knownIdentityForPublicKey(d.publicKey);await recordEvent(req,'authentication_proof_rejected',knownIdentity,{reason:'invalid_or_expired_proof'});return send(res,401,{error:'Challenge proof invalid, expired or already used'});}
   const result=await pool.query('UPDATE aegis_devices SET last_seen_at=NOW() WHERE public_key=$1 AND revoked_at IS NULL RETURNING device_id,identity_code,label,created_at,last_seen_at',[decode(d.publicKey)]);
   if(!result.rowCount){const knownIdentity=await knownIdentityForPublicKey(d.publicKey);await recordEvent(req,'authentication_denied',knownIdentity,{reason:'unknown_or_revoked_device'});return send(res,403,{error:'Device is not registered or has been revoked'});}
   const token=await issueSession(result.rows[0].device_id);await recordEvent(req,'device_authenticated',result.rows[0].identity_code,{deviceId:result.rows[0].device_id});return send(res,200,{authenticated:true,device:result.rows[0],token,tokenExpiresInDays:TOKEN_TTL_DAYS});
  }

  if(req.method==='PUT'&&url.pathname==='/v1/retention/policy'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const d=await readBody(req),checked=validateRetentionPolicy(d);if(!checked.ok)return send(res,400,{error:checked.error});
   const p=checked.value;
   await pool.query(`INSERT INTO aegis_retention_policies(identity_code,scope,conversation_id,mode,days,updated_at) VALUES($1,$2,$3,$4,$5,NOW()) ON CONFLICT(identity_code,scope,conversation_id) DO UPDATE SET mode=EXCLUDED.mode,days=EXCLUDED.days,updated_at=NOW()`,[current.identity_code,p.scope,p.conversationId,p.mode,p.days]);
   if(p.mode==='timed') await pool.query(`UPDATE aegis_retained_items SET expires_at=created_at+($4 || ' days')::interval WHERE identity_code=$1 AND scope=$2 AND conversation_id=$3`,[current.identity_code,p.scope,p.conversationId,String(p.days)]); else await pool.query('UPDATE aegis_retained_items SET expires_at=NULL WHERE identity_code=$1 AND scope=$2 AND conversation_id=$3',[current.identity_code,p.scope,p.conversationId]);
   return send(res,200,{saved:true,policy:p});
  }
  if(req.method==='POST'&&url.pathname==='/v1/retention/leave'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const d=await readBody(req);if(!['chats','rooms'].includes(d.scope)||typeof d.conversationId!=='string'||!/^[A-Za-z0-9_-]{8,80}$/.test(d.conversationId))return send(res,400,{error:'Invalid conversation reference'});
   const policy=await pool.query('SELECT mode FROM aegis_retention_policies WHERE identity_code=$1 AND scope=$2 AND conversation_id=$3',[current.identity_code,d.scope,d.conversationId]);
   if(policy.rows[0]?.mode==='leave'){const deleted=await pool.query('DELETE FROM aegis_retained_items WHERE identity_code=$1 AND scope=$2 AND conversation_id=$3',[current.identity_code,d.scope,d.conversationId]);return send(res,200,{deleted:deleted.rowCount,mode:'leave'});}
   return send(res,200,{deleted:0,mode:policy.rows[0]?.mode||'default'});
  }
  if(req.method==='POST'&&url.pathname==='/v1/retention/items'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const d=await readBody(req);if(!['chats','rooms'].includes(d.scope)||typeof d.conversationId!=='string'||!/^[A-Za-z0-9_-]{8,80}$/.test(d.conversationId)||typeof d.ciphertext!=='string'||d.ciphertext.length<16||d.ciphertext.length>12000||!/^[A-Za-z0-9+/]+={0,2}$/.test(d.ciphertext))return send(res,400,{error:'A valid conversation reference and base64 ciphertext are required'});
   const policy=await pool.query('SELECT mode,days FROM aegis_retention_policies WHERE identity_code=$1 AND scope=$2 AND conversation_id=$3',[current.identity_code,d.scope,d.conversationId]);
   const expiry=policy.rows[0]?.mode==='timed'?expiryForPolicy(policy.rows[0]):null;
   const saved=await pool.query('INSERT INTO aegis_retained_items(item_id,identity_code,scope,conversation_id,ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING item_id,created_at,expires_at',[crypto.randomUUID(),current.identity_code,d.scope,d.conversationId,d.ciphertext,expiry]);
   return send(res,201,{item:saved.rows[0],storage:'ciphertext-only',note:'Client-side encryption is required; this endpoint does not implement end-to-end key exchange or room membership controls.'});
  }
  if(req.method==='GET'&&url.pathname==='/v1/retention/items'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const scope=url.searchParams.get('scope'),conversationId=url.searchParams.get('conversationId');if(!['chats','rooms'].includes(scope)||!conversationId||!/^[A-Za-z0-9_-]{8,80}$/.test(conversationId))return send(res,400,{error:'Valid scope and conversationId are required'});
   const rows=await pool.query('SELECT item_id,ciphertext,created_at,expires_at FROM aegis_retained_items WHERE identity_code=$1 AND scope=$2 AND conversation_id=$3 AND (expires_at IS NULL OR expires_at>NOW()) ORDER BY created_at',[current.identity_code,scope,conversationId]);return send(res,200,{items:rows.rows});
  }
  // Encrypted mailbox relay: clients must encrypt and authenticate message payloads before upload.
  // The server routes opaque ciphertext only; this endpoint is not a key exchange protocol.
  if(req.method==='POST'&&url.pathname==='/v1/messages'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const d=await readBody(req);
   if(typeof d.recipientIdentity!=='string'||!/^AEGIS-[A-F0-9]{4}(?:-[A-F0-9]{4}){4}$/.test(d.recipientIdentity)||typeof d.ciphertext!=='string'||d.ciphertext.length<32||d.ciphertext.length>12000||!/^[A-Za-z0-9+/]+={0,2}$/.test(d.ciphertext))return send(res,400,{error:'A valid recipient identity and base64 ciphertext are required'});
   const recipient=await pool.query('SELECT 1 FROM aegis_devices WHERE identity_code=$1 AND revoked_at IS NULL LIMIT 1',[d.recipientIdentity]);
   if(!recipient.rowCount)return send(res,404,{error:'Recipient identity not found'});
   const saved=await pool.query('INSERT INTO aegis_message_mailbox(message_id,sender_identity,recipient_identity,ciphertext) VALUES($1,$2,$3,$4) RETURNING message_id,created_at,expires_at',[crypto.randomUUID(),current.identity_code,d.recipientIdentity,d.ciphertext]);
   return send(res,201,{message:saved.rows[0],storage:'ciphertext-only',expiresInDays:30,note:'Encrypt and authenticate messages on client devices before sending. This relay does not provide key exchange.'});
  }
  if(req.method==='GET'&&url.pathname==='/v1/messages'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   await pool.query('DELETE FROM aegis_message_mailbox WHERE expires_at<=NOW()');
   const rows=await pool.query('SELECT message_id,sender_identity,ciphertext,created_at,expires_at FROM aegis_message_mailbox WHERE recipient_identity=$1 AND expires_at>NOW() ORDER BY created_at ASC LIMIT 100',[current.identity_code]);
   return send(res,200,{messages:rows.rows,storage:'ciphertext-only'});
  }
  const messageDelete=url.pathname.match(/^\/v1\/messages\/([0-9a-f-]+)$/i);
  if(req.method==='DELETE'&&messageDelete){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const removed=await pool.query('DELETE FROM aegis_message_mailbox WHERE message_id=$1 AND recipient_identity=$2 RETURNING message_id',[messageDelete[1],current.identity_code]);
   if(!removed.rowCount)return send(res,404,{error:'Message not found'});
   return send(res,200,{deleted:true,messageId:removed.rows[0].message_id});
  }
  if(req.method==='GET'&&url.pathname==='/v1/security/events'){const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});const rows=await pool.query('SELECT event_id,event_type,source_ip,user_agent,details,created_at FROM aegis_security_events WHERE identity_code=$1 ORDER BY created_at DESC LIMIT 100',[current.identity_code]);return send(res,200,{events:rows.rows,retentionNote:'Latest 100 events; source IP is network metadata and may identify a shared gateway, not a person.'});}
  if(req.method==='GET'&&url.pathname==='/v1/devices'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const rows=await pool.query('SELECT device_id,identity_code,label,created_at,last_seen_at,revoked_at,(device_id=$2) AS is_current FROM aegis_devices WHERE identity_code=$1 ORDER BY created_at',[current.identity_code,current.device_id]);return send(res,200,{devices:rows.rows});
  }
  const revoke=url.pathname.match(/^\/v1\/devices\/([0-9a-f-]+)\/revoke$/i);
  if(req.method==='POST'&&revoke){const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});const target=revoke[1];const result=await pool.query('UPDATE aegis_devices SET revoked_at=NOW() WHERE device_id=$1 AND identity_code=$2 AND revoked_at IS NULL RETURNING device_id',[target,current.identity_code]);if(!result.rowCount)return send(res,404,{error:'Device not found or already revoked'});await pool.query('DELETE FROM aegis_sessions WHERE device_id=$1',[target]);await recordEvent(req,'device_revoked',current.identity_code,{deviceId:target});return send(res,200,{revoked:true,deviceId:target});}
  return send(res,404,{error:'Not found'});
 } catch(e){return send(res,e.status||500,{error:e.status?e.message:'Request could not be completed'});}
}
const server=http.createServer((req,res)=>route(req,res).catch(()=>send(res,500,{error:'Internal server error'})));
init().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`AEGIS backend listening on ${PORT}`))).catch(e=>{console.error(`Startup failed: ${e.message}`);process.exit(1);});
process.on('SIGTERM',async()=>{server.close();await pool.end();process.exit(0);});
