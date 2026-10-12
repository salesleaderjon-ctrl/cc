// Decrypts the vault on the fly. Plaintext only ever exists inside this browser.
const SCOPE = self.registration.scope;               // https://host/<token>/
const SCOPE_PATH = new URL(SCOPE).pathname;
const SITE = SCOPE + 's/';
let manifest = null;
// Offline cache: ciphertext + the public unlock page only. Plaintext is never cached.
const CACHE = 'cc-cipher-v2';   // v2 (Oct 8): tab bar fix; bump to force old clients onto a fresh cache
async function netFirst(req, cacheKey) {
  const c = await caches.open(CACHE);
  try {
    const r = await fetch(typeof req === 'string' ? req : req.url, { cache: 'no-store', credentials: 'same-origin' });
    if (r.ok) c.put(cacheKey, r.clone());
    return r;
  } catch (err) {
    const hit = await c.match(cacheKey);
    if (hit) return hit;
    throw err;
  }
}
async function blob(id) {                             // blob ids are content hashes: cache-first is safe
  const c = await caches.open(CACHE), k = SCOPE + 'vault/' + id + '.bin';
  const hit = await c.match(k);
  if (hit) return hit;
  const r = await fetch(k);
  if (r.ok) c.put(k, r.clone());
  return r;
}
async function prune(m) {
  const keep = new Set(Object.values(m.files).map(f => SCOPE + 'vault/' + f.id + '.bin'));
  const c = await caches.open(CACHE);
  for (const req of await c.keys()) if (/\/vault\/[0-9a-f]{32}\.bin$/.test(req.url) && !keep.has(req.url)) c.delete(req);
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);   // drop old cache versions
  await self.clients.claim();
})()));
self.addEventListener('message', e => { if (e.data === 'reset') manifest = null; });

function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('cc-vault', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbOp(mode, fn) {
  const db = await idb();
  return new Promise((res, rej) => {
    const tx = db.transaction('k', mode); const req = fn(tx.objectStore('k'));
    tx.oncomplete = () => res(req && req.result); tx.onerror = () => rej(tx.error);
  });
}
async function getKey() {
  const rec = await idbOp('readonly', s => s.get('key'));
  if (!rec || (rec.exp && Date.now() > rec.exp)) return null;
  if (rec.raw) return crypto.subtle.importKey('raw', rec.raw, 'AES-GCM', false, ['decrypt']);
  return rec.key;
}
async function clearKey() { await idbOp('readwrite', s => s.delete('key')); manifest = null; await caches.delete(CACHE); }

async function decrypt(key, buf, aad) {
  const b = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12), additionalData: new TextEncoder().encode(aad) }, key, b.slice(12));
}
async function getManifest(key, fresh) {
  if (manifest && !fresh) return manifest;
  const r = await netFirst(SCOPE + 'vault/manifest.bin', SCOPE + 'vault/manifest.bin');
  if (!r.ok) throw new Error('manifest ' + r.status);
  manifest = JSON.parse(new TextDecoder().decode(await decrypt(key, await r.arrayBuffer(), 'manifest')));
  prune(manifest).catch(() => {});
  return manifest;
}
const SEC = { 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' };

function locked(req, rel) {
  if (req.mode === 'navigate') return Response.redirect(SCOPE + '?next=' + encodeURIComponent(rel), 302);
  return new Response('locked', { status: 403, headers: SEC });
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  // The public unlock page and the vault index work offline (network-first, cached copy as fallback).
  const pub = url.pathname.slice(SCOPE_PATH.length);
  if (e.request.method === 'GET' && (pub === '' || pub === 'index.html' || pub === 'icon.svg' || pub === 'vault/meta.json' || pub === 'vault/manifest.bin')) {
    const k = SCOPE + (pub === '' ? 'index.html' : pub);
    e.respondWith(netFirst(e.request, k).catch(() => new Response('Offline', { status: 503, headers: SEC })));
    return;
  }
  if (!url.pathname.startsWith(SCOPE_PATH + 's/')) return;
  e.respondWith(handle(e.request, url));
});

async function handle(req, url) {
  let rel = decodeURIComponent(url.pathname.slice(SCOPE_PATH.length + 2));
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  const key = await getKey();
  if (!key) return locked(req, rel);
  let m;
  try { m = await getManifest(key, req.mode === 'navigate'); }
  catch (err) {
    if (err instanceof DOMException || err.name === 'OperationError') { await clearKey(); return locked(req, rel); }
    return new Response('Vault unavailable, try again shortly.', { status: 503, headers: { ...SEC, 'Content-Type': 'text/plain' } });
  }
  let ent = m.files[rel];
  if (!ent && m.files[rel + '/index.html']) return Response.redirect(SITE + rel + '/' + url.search, 302);
  if (!ent && !/\.[a-z0-9]+$/i.test(rel) && m.files[rel + '.html']) ent = m.files[rel + '.html'];
  if (!ent) return new Response('<!doctype html><meta name=viewport content="width=device-width"><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem">Not found. <a style="color:#F66025" href="' + SITE + '">Home</a>', { status: 404, headers: { ...SEC, 'Content-Type': 'text/html; charset=utf-8' } });
  const r = await blob(ent.id);
  if (!r.ok) { manifest = null; return new Response('Updated just now, reload.', { status: 503, headers: SEC }); }
  let pt;
  try { pt = await decrypt(key, await r.arrayBuffer(), ent.id); }
  catch { await clearKey(); return locked(req, rel); }
  const headers = { ...SEC, 'Content-Type': ent.type };
  if (ent.type.startsWith('application/pdf')) headers['Content-Disposition'] = 'inline; filename="' + rel.split('/').pop().replace(/"/g, '') + '"';
  return new Response(pt, { status: 200, headers });
}
