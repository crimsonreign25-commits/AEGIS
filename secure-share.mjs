const encoder = new TextEncoder();
const decoder = new TextDecoder();
export const SHARE_VERSION = 1;
export const MAX_SHARE_BYTES = 20 * 1024 * 1024;
const cryptoApi = () => globalThis.crypto;
const b64 = (bytes) => BufferlessBase64.encode(bytes);
const unb64 = (value) => BufferlessBase64.decode(value);
const BufferlessBase64 = {
  encode(bytes) { let s=''; for (const b of bytes) s+=String.fromCharCode(b); return btoa(s); },
  decode(value) { const s=atob(value); return Uint8Array.from(s, c=>c.charCodeAt(0)); }
};
const random = n => cryptoApi().getRandomValues(new Uint8Array(n));
async function deriveCodeKey(code, salt, iterations=310000) {
  if (typeof code !== 'string' || code.length < 8 || code.length > 128) throw new Error('Security code must be 8–128 characters.');
  const material = await cryptoApi().subtle.importKey('raw', encoder.encode(code), 'PBKDF2', false, ['deriveKey']);
  return cryptoApi().subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations}, material, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}
export async function createSecureShare(file, options, code) {
  if (!(file instanceof Blob)) throw new Error('Choose a file to share.');
  if (file.size > MAX_SHARE_BYTES) throw new Error('Files must be 20 MB or smaller.');
  if (!options || !['view','download','both'].includes(options.allowedMode)) throw new Error('Choose valid recipient access options.');
  const salt=random(16), wrapIv=random(12), fileIv=random(12);
  const fileKey=await cryptoApi().subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const rawFileKey=new Uint8Array(await cryptoApi().subtle.exportKey('raw',fileKey));
  const wrappingKey=await deriveCodeKey(code,salt);
  const wrappedKey=await cryptoApi().subtle.encrypt({name:'AES-GCM',iv:wrapIv},wrappingKey,rawFileKey);
  const meta={name:String(file.name||'shared-file').slice(0,180),type:String(file.type||'application/octet-stream').slice(0,120),size:file.size,allowedMode:options.allowedMode,expiresAt:options.expiresAt||null,createdAt:new Date().toISOString()};
  const aad=encoder.encode(JSON.stringify(meta));
  const ciphertext=await cryptoApi().subtle.encrypt({name:'AES-GCM',iv:fileIv,additionalData:aad},fileKey,await file.arrayBuffer());
  return {format:'AEGIS-SECURE-SHARE',version:SHARE_VERSION,meta,salt:b64(salt),wrapIv:b64(wrapIv),wrappedKey:b64(new Uint8Array(wrappedKey)),fileIv:b64(fileIv),ciphertext:b64(new Uint8Array(ciphertext))};
}
export async function openSecureShare(pkg, code, recipientChoice) {
  if (!pkg || pkg.format!=='AEGIS-SECURE-SHARE' || pkg.version!==SHARE_VERSION) throw new Error('Unsupported or invalid AEGIS share package.');
  if (!['view','download'].includes(recipientChoice)) throw new Error('Choose protected viewing or secure download.');
  if (pkg.meta.allowedMode!== 'both' && pkg.meta.allowedMode!==recipientChoice) throw new Error('The sender did not allow this access mode.');
  if (pkg.meta.expiresAt && Date.now()>Date.parse(pkg.meta.expiresAt)) throw new Error('This share has expired.');
  if (!Number.isFinite(pkg.meta.size) || pkg.meta.size<0 || pkg.meta.size>MAX_SHARE_BYTES) throw new Error('Invalid shared file size.');
  const wrappingKey=await deriveCodeKey(code,unb64(pkg.salt));
  let rawKey;
  try { rawKey=await cryptoApi().subtle.decrypt({name:'AES-GCM',iv:unb64(pkg.wrapIv)},wrappingKey,unb64(pkg.wrappedKey)); }
  catch { throw new Error('Incorrect security code or damaged share package.'); }
  const fileKey=await cryptoApi().subtle.importKey('raw',rawKey,{name:'AES-GCM'},false,['decrypt']);
  const aad=encoder.encode(JSON.stringify(pkg.meta));
  let plaintext;
  try { plaintext=await cryptoApi().subtle.decrypt({name:'AES-GCM',iv:unb64(pkg.fileIv),additionalData:aad},fileKey,unb64(pkg.ciphertext)); }
  catch { throw new Error('File authentication failed. The package may have been modified.'); }
  if (plaintext.byteLength!==pkg.meta.size) throw new Error('Shared file size check failed.');
  return {blob:new Blob([plaintext],{type:pkg.meta.type}),name:pkg.meta.name,mode:recipientChoice};
}
export function serializeSecureShare(pkg) { return new Blob([JSON.stringify(pkg)],{type:'application/vnd.aegis.secure-share+json'}); }
export async function parseSecureShare(file) { let pkg; try { pkg=JSON.parse(await file.text()); } catch { throw new Error('This is not a valid AEGIS share package.'); } if(pkg?.format!=='AEGIS-SECURE-SHARE') throw new Error('This is not an AEGIS secure share.'); return pkg; }
