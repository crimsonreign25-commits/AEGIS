import http from 'node:http';
import crypto from 'node:crypto';
import pg from 'pg';
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined, max: 5 });
const PORT = Number(process.env.PORT || 10000);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
const challenges = new Map();
const limits = new Map();
const MAX_BODY = 16 * 1024;
const TOKEN_TTL_DAYS = 30;
const send = (res, status, value) => { res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Access-Control-Allow-Origin': ALLOWED_ORIGIN || 'null','Vary':'Origin'}); res.end(JSON.stringify(value)); };
function cors(req,res) { const origin=req.headers.origin; if (ALLOWED_ORIGIN && origin && origin!==ALLOWED_ORIGIN) return false; if (ALLOWED_ORIGIN && origin===ALLOWED_ORIGIN) res.setHeader('Access-Control-Allow-Origin',ALLOWED_ORIGIN); res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS'); res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization'); res.setHeader('Access-Control-Max-Age','600'); return true; }
async function readBody(req) { let raw=''; for await (const chunk of req) { raw+=chunk; if (Buffer.byteLength(raw)>MAX_BODY) throw Object.assign(new Error('Request too large'),{status:413}); } try { return JSON.parse(raw||'{}'); } catch { throw Object.assign(new Error('Invalid JSON'),{status:400}); } }
const decode = value => Buffer.from(value,'base64');
const encode = value => Buffer.from(value).toString('base64');
function validPublicKey(value) { if(typeof value!=='string'||value.length>256) return false; const b=decode(value); return b.length===65&&b[0]===4&&encode(b)===value; }
function fingerprint(raw) { const h=crypto.createHash('sha256').update(raw).digest('hex').slice(0,20).toUpperCase(); return `AEGIS-${h.match(/.{1,4}/g).join('-')}`; }
function publicKeyObject(raw) { const prefix=Buffer.from('3059301306072A8648CE3D020106082A8648CE3D030107034200','hex'); return crypto.createPublicKey({key:Buffer.concat([prefix,raw]),format:'der',type:'spki'}); }
function checkSignature(raw,message,signature) { try { const sig=decode(signature); return sig.length===64&&crypto.verify('sha256',Buffer.from(message),{key:publicKeyObject(raw),dsaEncoding:'ieee-p1363'},sig); } catch { return false; } }
function newChallenge(publicKey) { const id=crypto.randomUUID(), nonce=crypto.randomBytes(32).toString('base64url'); const message=`AEGIS-AUTH-V1\n${id}\n${nonce}\n${Date.now()}`; challenges.set(id,{publicKey,message,expires:Date.now()+120000}); return {challengeId:id,message,expiresInSeconds:120}; }
function useChallenge(id,key,signature) { const item=challenges.get(id); challenges.delete(id); if(!item||item.expires<Date.now()||item.publicKey!==key) return false; return checkSignature(decode(key),item.message,signature); }
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
async function auth(req) { const value=req.headers.authorization||''; if(!value.startsWith('Bearer ')) return null; const hash=tokenHash(value.slice(7)); const result=await pool.query(`SELECT d.device_id,d.identity_code,d.label,d.created_at,d.last_seen_at FROM aegis_sessions s JOIN aegis_devices d ON d.device_id=s.device_id WHERE s.token_hash=$1 AND s.expires_at>NOW() AND d.revoked_at IS NULL`,[hash]); if(!result.rowCount) return null; await pool.query('UPDATE aegis_devices SET last_seen_at=NOW() WHERE device_id=$1',[result.rows[0].device_id]); return result.rows[0]; }
async function issueSession(deviceId) { const token=crypto.randomBytes(32).toString('base64url'); await pool.query('INSERT INTO aegis_sessions(token_hash,device_id,expires_at) VALUES($1,$2,NOW()+($3 || \' days\')::interval)',[tokenHash(token),deviceId,String(TOKEN_TTL_DAYS)]); return token; }
async function init() { if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required'); await pool.query(`CREATE TABLE IF NOT EXISTS aegis_devices(device_id UUID PRIMARY KEY,identity_code TEXT NOT NULL,public_key BYTEA NOT NULL UNIQUE,label TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),revoked_at TIMESTAMPTZ); CREATE INDEX IF NOT EXISTS aegis_devices_identity_idx ON aegis_devices(identity_code); CREATE TABLE IF NOT EXISTS aegis_sessions(token_hash TEXT PRIMARY KEY,device_id UUID NOT NULL REFERENCES aegis_devices(device_id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL); CREATE INDEX IF NOT EXISTS aegis_sessions_device_idx ON aegis_sessions(device_id);`); }
function rateLimit(req) { const ip=req.socket.remoteAddress||'unknown',now=Date.now(),v=limits.get(ip)||{start:now,count:0}; if(now-v.start>60000){v.start=now;v.count=0;} v.count++; limits.set(ip,v); return v.count<=60; }
async function route(req,res) {
 if(!cors(req,res)) return send(res,403,{error:'Origin not allowed'});
 if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
 if(!rateLimit(req)) return send(res,429,{error:'Rate limit exceeded'});
 const url=new URL(req.url,'http://localhost');
 if(req.method==='GET'&&url.pathname==='/health'){try{await pool.query('SELECT 1');return send(res,200,{ok:true,service:'aegis-backend',version:'0.4.0',database:'connected'});}catch{return send(res,503,{ok:false,database:'unavailable'});}}
 try {
  if(req.method==='POST'&&url.pathname==='/v1/challenges'){const d=await readBody(req);if(!validPublicKey(d.publicKey))return send(res,400,{error:'Valid uncompressed P-256 public key required'});return send(res,200,newChallenge(d.publicKey));}
  if(req.method==='POST'&&url.pathname==='/v1/devices/register'){
   const d=await readBody(req);if(!validPublicKey(d.publicKey)||typeof d.challengeId!=='string'||typeof d.signature!=='string')return send(res,400,{error:'Invalid registration proof'});
   if(!useChallenge(d.challengeId,d.publicKey,d.signature))return send(res,401,{error:'Challenge proof invalid, expired or already used'});
   const raw=decode(d.publicKey),code=fingerprint(raw),label=typeof d.label==='string'?d.label.trim().slice(0,48):'';
   const result=await pool.query(`INSERT INTO aegis_devices(device_id,identity_code,public_key,label) VALUES($1,$2,$3,$4) ON CONFLICT(public_key) DO UPDATE SET last_seen_at=NOW(),revoked_at=NULL,label=EXCLUDED.label RETURNING device_id,identity_code,label,created_at,last_seen_at`,[crypto.randomUUID(),code,raw,label]);
   const token=await issueSession(result.rows[0].device_id);return send(res,201,{device:result.rows[0],token,tokenExpiresInDays:TOKEN_TTL_DAYS});
  }
  if(req.method==='POST'&&url.pathname==='/v1/devices/authenticate'){
   const d=await readBody(req);if(!validPublicKey(d.publicKey)||typeof d.challengeId!=='string'||typeof d.signature!=='string')return send(res,400,{error:'Invalid authentication proof'});
   if(!useChallenge(d.challengeId,d.publicKey,d.signature))return send(res,401,{error:'Challenge proof invalid, expired or already used'});
   const result=await pool.query('UPDATE aegis_devices SET last_seen_at=NOW() WHERE public_key=$1 AND revoked_at IS NULL RETURNING device_id,identity_code,label,created_at,last_seen_at',[decode(d.publicKey)]);
   if(!result.rowCount)return send(res,403,{error:'Device is not registered or has been revoked'});
   const token=await issueSession(result.rows[0].device_id);return send(res,200,{authenticated:true,device:result.rows[0],token,tokenExpiresInDays:TOKEN_TTL_DAYS});
  }
  if(req.method==='GET'&&url.pathname==='/v1/devices'){
   const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});
   const rows=await pool.query('SELECT device_id,identity_code,label,created_at,last_seen_at,revoked_at,(device_id=$2) AS is_current FROM aegis_devices WHERE identity_code=$1 ORDER BY created_at',[current.identity_code,current.device_id]);return send(res,200,{devices:rows.rows});
  }
  const revoke=url.pathname.match(/^\/v1\/devices\/([0-9a-f-]+)\/revoke$/i);
  if(req.method==='POST'&&revoke){const current=await auth(req);if(!current)return send(res,401,{error:'Authentication required'});const target=revoke[1];const result=await pool.query('UPDATE aegis_devices SET revoked_at=NOW() WHERE device_id=$1 AND identity_code=$2 AND revoked_at IS NULL RETURNING device_id',[target,current.identity_code]);if(!result.rowCount)return send(res,404,{error:'Device not found or already revoked'});await pool.query('DELETE FROM aegis_sessions WHERE device_id=$1',[target]);return send(res,200,{revoked:true,deviceId:target});}
  return send(res,404,{error:'Not found'});
 } catch(e){return send(res,e.status||500,{error:e.status?e.message:'Request could not be completed'});}
}
const server=http.createServer((req,res)=>route(req,res).catch(()=>send(res,500,{error:'Internal server error'})));
init().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`AEGIS backend listening on ${PORT}`))).catch(e=>{console.error(`Startup failed: ${e.message}`);process.exit(1);});
process.on('SIGTERM',async()=>{server.close();await pool.end();process.exit(0);});
