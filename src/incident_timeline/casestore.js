/* ORISECT case store: keeps a signed copy of each investigation in this browser.
 *
 * The hosted app runs on short-lived serverless instances, each with its own
 * temporary disk, so a case uploaded to one instance may be missing (or older)
 * on the instance that answers the next request. The server hands the browser a
 * signed archive of the case after every change; when an instance answers
 * "not found" (404) or "stale" (409), caseFetch sends the archive back and
 * retries. Running locally, the server never sends archives and none of this
 * activates.
 */
(function (root) {
  'use strict';
  const DB = 'orisect', STORE = 'cases', KEEP_DAYS = 14;
  let dbPromise = null;

  function db() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      let req;
      try { req = indexedDB.open(DB, 1); } catch (err) { reject(err); return; }
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }).catch(() => null); // private windows can block IndexedDB; the app still works without it
    return dbPromise;
  }
  async function tx(mode, fn) {
    const d = await db();
    if (!d) return undefined;
    return new Promise((resolve, reject) => {
      const t = d.transaction(STORE, mode), store = t.objectStore(STORE);
      const req = fn(store);
      t.oncomplete = () => resolve(req && req.result);
      t.onerror = () => reject(t.error);
    }).catch(() => undefined);
  }

  const memory = new Map();
  async function get(caseId) {
    if (memory.has(caseId)) return memory.get(caseId);
    const rec = await tx('readonly', s => s.get(caseId));
    if (rec) memory.set(caseId, rec);
    return rec || null;
  }
  async function save(caseId, rec) {
    const current = await get(caseId);
    if (current && seq(current.version) > seq(rec.version)) return; // never replace newer with older
    const value = { ...rec, savedAt: Date.now() };
    memory.set(caseId, value);
    await tx('readwrite', s => s.put(value, caseId));
  }
  async function prune() {
    const cutoff = Date.now() - KEEP_DAYS * 864e5;
    await tx('readwrite', s => {
      const req = s.openCursor();
      req.onsuccess = () => { const c = req.result; if (!c) return; if ((c.value.savedAt || 0) < cutoff) c.delete(); c.continue(); };
      return req;
    });
  }
  const seq = v => Number(String(v || '0').split(':')[0]) || 0;

  function fromHeaders(r) {
    const version = r.headers.get('X-Orisect-Version'), signature = r.headers.get('X-Orisect-Signature');
    return version && signature ? { version, signature } : null;
  }
  function base64ToBlob(b64) {
    const bin = atob(b64), bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Blob([bytes], { type: 'application/gzip' });
  }

  /** Save the archive a response carried: a gzip body, or `_archive` fields in a JSON body. */
  async function absorb(caseId, r, json) {
    if (json && json._archive) {
      await save(caseId, { version: json._version, signature: json._signature, archive: base64ToBlob(json._archive) });
      delete json._archive; delete json._version; delete json._signature;
      return true;
    }
    const meta = fromHeaders(r);
    if (meta && /gzip/.test(r.headers.get('Content-Type') || '')) {
      await save(caseId, { ...meta, archive: await r.blob() });
      return true;
    }
    return false;
  }

  let hosted = false; // set once a server response carries a case version
  const restoring = new Map();
  /** Send the stored archive back to whichever instance answers. Resolves true on success. */
  function restore(caseId) {
    if (restoring.has(caseId)) return restoring.get(caseId);
    const p = (async () => {
      const rec = await get(caseId);
      if (!rec) return false;
      const r = await fetch(`/api/case-restore?case=${encodeURIComponent(caseId)}`, {
        method: 'POST', body: rec.archive, cache: 'no-store',
        headers: { 'Content-Type': 'application/gzip', 'X-Orisect-Version': rec.version, 'X-Orisect-Signature': rec.signature }
      }).catch(() => null);
      if (!r) return false;
      await r.json().catch(() => null); // finish the response so the connection is released
      return r.ok;
    })().finally(() => setTimeout(() => restoring.delete(caseId), 0));
    restoring.set(caseId, p);
    return p;
  }

  /**
   * fetch() for one investigation's API. Tells the server which version this
   * browser holds; restores and retries (up to twice) when the instance lacks it.
   */
  async function caseFetch(caseId, url, init = {}, attempt = 0) {
    const rec = caseId ? await get(caseId) : null;
    const headers = new Headers(init.headers || {});
    if (rec) headers.set('X-Orisect-Expect', rec.version);
    headers.set('X-Orisect-Archive', '1');
    const r = await fetch(url, { ...init, headers, cache: 'no-store' });
    if (r.headers.get('X-Orisect-Version')) hosted = true;
    if (rec && attempt < 2 && (r.status === 409 || r.status === 404)) {
      const body = await r.json().catch(() => ({})); // consumed here; only retried requests are returned
      const missing = r.status === 404 && /investigation not found/i.test(body.error || '');
      if ((r.status === 409 && body.stale) || missing) {
        if (root.OrisectStore.onRestore) root.OrisectStore.onRestore(true);
        const ok = await restore(caseId);
        if (root.OrisectStore.onRestore) root.OrisectStore.onRestore(false, ok);
        if (ok) return caseFetch(caseId, url, init, attempt + 1);
      }
      // Not recoverable: hand back an equivalent response, since this one's body has been read.
      return new Response(JSON.stringify(body), { status: r.status, headers: r.headers });
    }
    return r;
  }

  /** Fetch the archive for a case this browser has no copy of yet (opened from another device, say). */
  async function ensure(caseId) {
    if (!hosted || !caseId || await get(caseId)) return; // the local app keeps cases on disk
    const r = await fetch(`/api/case-archive?case=${encodeURIComponent(caseId)}`, { cache: 'no-store' }).catch(() => null);
    if (r && r.ok && await absorb(caseId, r)) return;
    if (r && r.body) r.body.cancel().catch(() => {}); // local app: no archives; release the connection
  }

  root.OrisectStore = { get, save, absorb, restore, caseFetch, ensure, prune, onRestore: null };
  setTimeout(prune, 4000);
})(window);
