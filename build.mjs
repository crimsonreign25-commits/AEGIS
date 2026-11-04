import { cp, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
const root = process.cwd(), out = path.join(root, 'dist');
await rm(out, {recursive:true, force:true});
await mkdir(out, {recursive:true});
for (const item of ['index.html','app.js','vault-store.mjs','secure-share.mjs','message-crypto.mjs','manifest.webmanifest','sw.js','src','public']) await cp(path.join(root,item), path.join(out,item), {recursive:true});
console.log('Built AEGIS PWA into dist/');
