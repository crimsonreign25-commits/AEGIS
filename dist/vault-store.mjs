const DB_NAME = 'aegis-private-data-v1';
const STORE_NAME = 'records';
const MAX_FILE_BYTES = 20 * 1024 * 1024;

export async function deriveLocalVaultKey(identity, subtle = globalThis.crypto.subtle) {
  if (!identity?.agreementPrivateKey || !identity?.agreementPublicKey || !identity?.identityCode) {
    throw new Error('The existing AEGIS identity is unavailable.');
  }
  const shared = await subtle.deriveBits(
    { name: 'ECDH', public: identity.agreementPublicKey },
    identity.agreementPrivateKey,
    256
  );
  const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(identity.identityCode), info: new TextEncoder().encode('AEGIS-LOCAL-VAULT-V1') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptRecord(key, value, subtle = globalThis.crypto.subtle) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ciphertext)), version: 1 };
}

export async function decryptRecord(key, record, subtle = globalThis.crypto.subtle) {
  if (!record || record.version !== 1 || !Array.isArray(record.iv) || !Array.isArray(record.ciphertext)) throw new Error('Encrypted record format is invalid.');
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(record.iv) }, key, new Uint8Array(record.ciphertext));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function openStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Could not open encrypted local storage.'));
  });
}
export async function putEncryptedRecord(record) {
  const db = await openStore();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(record);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error || new Error('Could not save encrypted data.')); };
  });
}
export async function getEncryptedRecords(kind) {
  const db = await openStore();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll();
    request.onsuccess = () => { const rows = request.result.filter(row => row.kind === kind).sort((a,b) => b.updatedAt.localeCompare(a.updatedAt)); db.close(); resolve(rows); };
    request.onerror = () => { db.close(); reject(request.error || new Error('Could not read encrypted data.')); };
  });
}
export async function deleteEncryptedRecord(id) {
  const db = await openStore();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error || new Error('Could not delete encrypted data.')); };
  });
}
export { MAX_FILE_BYTES };

export async function encryptBytes(key, bytes, subtle = globalThis.crypto.subtle) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv, ciphertext, version: 1 };
}
export async function decryptBytes(key, record, subtle = globalThis.crypto.subtle) {
  if (!record || record.version !== 1 || !record.iv || !(record.ciphertext instanceof ArrayBuffer)) throw new Error('Encrypted file format is invalid.');
  return subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(record.iv) }, key, record.ciphertext);
}
