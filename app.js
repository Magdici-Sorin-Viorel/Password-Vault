// ════════════════════════════════════════════════════════════════
// VAULT — app.js
// The UI is built only with createElement/textContent (never innerHTML),
// so text stored in entries can never execute as code.
// Code and comments are in English; user-facing strings are in Romanian.
// ════════════════════════════════════════════════════════════════
import * as C from './crypto.js';

const APP_VERSION = '5.2.0';

// Framing is not blocked on purpose: modern browsers partition the storage of a
// cross-site iframe, so a foreign site embedding the app only sees an empty vault.

// ── Helper DOM ─────────────────────────────────────────────────
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'ref') v(el);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}
const $app = document.getElementById('app');
const mount = (...nodes) => $app.replaceChildren(...nodes.filter(Boolean));

// ── Storage: IndexedDB ──────────────────────────────────────────
const DB = (() => {
  let dbp;
  const db = () => dbp ??= new Promise((res, rej) => {
    const r = indexedDB.open('vault', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  async function tx(mode, fn) {
    const d = await db();
    return new Promise((res, rej) => {
      const t = d.transaction('kv', mode);
      const req = fn(t.objectStore('kv'));
      t.oncomplete = () => res(req?.result);
      t.onerror = () => rej(t.error);
      t.onabort = () => rej(t.error);
    });
  }
  return {
    get: k => tx('readonly', s => s.get(k)),
    set: (k, v) => tx('readwrite', s => s.put(v, k)),
    clear: () => tx('readwrite', s => s.clear()),
  };
})();

// ── State ──────────────────────────────────────────────────────
const DEFAULT_SETTINGS = { autoLockMins: 5, hideLockSecs: 60, clipClearSecs: 30 };
const DEFAULT_POLICY = { wipeAfter: 4, countdown: 30 }; // self-destruct: after how many wrong PINs, countdown seconds
const DEFAULT_META = { fails: 0, lockUntil: 0, destructAt: 0, policy: { ...DEFAULT_POLICY } };
const LOCK_AFTER = 3;              // lock the app after 3 wrong PINs
const LOCK_MS = 5 * 60_000;        // … for 5 minutes
const PIN_LENGTHS = [4, 6, 8];
const S = {
  record: null,        // encrypted vault record from IndexedDB
  meta: { ...DEFAULT_META },
  key: null,           // non-extractable CryptoKey (only while unlocked)
  data: null,          // decrypted { entries, settings } (only while unlocked)
  query: '',
  timers: {},
  clipPending: false,
  external: false,     // a system dialog is open (file picker, fingerprint, share)
  holdLock: false,     // suspend auto-lock while the 24 words are being written down
  pending: null,       // vault built in memory, saved only after the word quiz passes
  saving: Promise.resolve(),
  gen: { length: 20, upper: true, lower: true, digits: true, symbols: true },
};

// ── Toast ──────────────────────────────────────────────────────
function toast(msg, kind = 'ok', ms = 2200) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show ' + kind;
  clearTimeout(S.timers.toast);
  S.timers.toast = setTimeout(() => { t.className = ''; }, ms);
}

// ── Modals ─────────────────────────────────────────────────────
function modal(title, body, { danger = false } = {}) {
  const ov = h('div', { class: 'overlay' });
  const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    h('div', { class: 'modal-head' },
      h('div', { class: 'modal-title' + (danger ? ' danger' : '') }, title),
      h('button', { class: 'modal-x', type: 'button', 'aria-label': 'Închide', title: 'Închide',
        onclick: () => { ov.onX?.(); ov.remove(); } }, '✕')),
    body);
  ov.append(box);
  ov.addEventListener('mousedown', e => { if (e.target === ov) { ov.onX?.(); ov.remove(); } });
  document.body.append(ov);
  ov.close = () => ov.remove();
  autoFocus(() => box.querySelector('input:not([type=checkbox]):not([type=range]), textarea'));
  return ov;
}
// Focus a field after render, but never steal focus from a field the user already tapped.
function autoFocus(getEl) {
  setTimeout(() => {
    const a = document.activeElement;
    if (!a || a === document.body || !document.contains(a)) getEl()?.focus();
  }, 50);
}
const closeAllModals = () => document.querySelectorAll('.overlay').forEach(o => o.remove());
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { const all = document.querySelectorAll('.overlay'); const top = all[all.length - 1]; top?.onX?.(); top?.remove(); }
});

// ── Small components ────────────────────────────────────────────
function pwInput(attrs = {}) {
  let input;
  const eye = h('button', { type: 'button', class: 'eye-btn', 'aria-label': 'Arată/ascunde', tabindex: '-1',
    onclick: () => { input.type = input.type === 'password' ? 'text' : 'password'; eye.textContent = input.type === 'password' ? '👁' : '🙈'; } }, '👁');
  input = h('input', { type: 'password', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', class: 'has-icon', ...attrs });
  const wrap = h('div', { class: 'input-wrap' }, input, eye);
  wrap.input = input;
  return wrap;
}
function textInput(attrs = {}) {
  return h('input', { type: 'text', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', ...attrs });
}
function field(label, control, hint) {
  return h('div', { class: 'field' }, label && h('label', null, label), control, hint && h('div', { class: 'hint' }, hint));
}
function strengthMeter(input) {
  const fill = h('div', { class: 'strength-fill' });
  const label = h('div', { class: 'strength-label' }, '—');
  const update = () => {
    const s = C.strength(input.value);
    const colors = ['var(--red)', 'var(--red)', 'var(--orange)', 'var(--green)', 'var(--green)'];
    fill.style.width = input.value ? Math.max(8, Math.min(100, s.bits)) + '%' : '0%';
    fill.style.background = colors[s.score];
    label.style.color = input.value ? colors[s.score] : '';
    label.textContent = input.value ? `${s.label} · ~${s.bits} biți` : '—';
  };
  input.addEventListener('input', update);
  update();
  const el = h('div', { class: 'strength-wrap' }, h('div', { class: 'strength-bar' }, fill), label);
  el.update = update;
  return el;
}
function busy(btn, text) {
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = text;
  return () => { btn.disabled = false; btn.textContent = old; };
}
function download(name, text, mime = 'application/json') {
  S.external = true;
  const a = h('a', { download: name });
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => { URL.revokeObjectURL(a.href); S.external = false; }, 4000);
}
const fmtDate = ts => ts ? new Date(ts).toLocaleString('ro-RO', { dateStyle: 'medium', timeStyle: 'short' }) : '—';

// PIN validation: digits only, chosen length, no obvious patterns
function checkPin(pin, confirm, len) {
  if (!new RegExp('^\\d{' + len + '}$').test(pin)) return `PIN-ul trebuie să aibă exact ${len} cifre.`;
  if (/^(\d)\1+$/.test(pin)) return 'PIN-ul nu poate avea toate cifrele la fel.';
  const d = [...pin].map(Number);
  const step = d[1] - d[0];
  if (Math.abs(step) === 1 && d.every((x, i) => i === 0 || x - d[i - 1] === step)) return 'PIN-ul nu poate fi o secvență (ex. 1234, 4321).';
  if (pin !== confirm) return 'PIN-urile nu coincid.';
  return null;
}

// PIN field: numeric keypad, dot indicator, auto-submit on the last digit
function pinField(len, { placeholder = 'PIN', onComplete } = {}) {
  const dots = h('div', { class: 'pin-display', 'aria-hidden': 'true' });
  const input = h('input', { type: 'password', inputmode: 'numeric', pattern: '[0-9]*', autocomplete: 'off',
    maxlength: len || 64, placeholder: len ? `${placeholder} — ${len} cifre` : placeholder, class: 'pin-input' });
  const draw = () => dots.replaceChildren(...Array.from({ length: len || 0 }, (_, i) =>
    h('div', { class: 'pin-dot' + (i < input.value.length ? ' filled' : '') })));
  input.addEventListener('input', () => {
    if (len) input.value = input.value.replace(/\D/g, '').slice(0, len);
    draw();
    if (len && onComplete && input.value.length === len) setTimeout(onComplete, 80);
  });
  draw();
  const wrap = h('div', null, len ? dots : null, input);
  wrap.input = input;
  wrap.error = () => { dots.classList.add('error'); setTimeout(() => dots.classList.remove('error'), 500); input.value = ''; draw(); };
  wrap.setLen = n => { len = n; input.maxLength = n; input.placeholder = `${placeholder} — ${n} cifre`; input.value = ''; draw(); };
  return wrap;
}

function lengthPicker(current, onPick) {
  const wrap = h('div', { class: 'pin-length-selector', role: 'radiogroup', 'aria-label': 'Lungime PIN' });
  const draw = v => wrap.replaceChildren(...PIN_LENGTHS.map(n => h('button', {
    type: 'button', class: 'pin-len-btn' + (n === v ? ' active' : ''), role: 'radio', 'aria-checked': String(n === v),
    onclick: () => { draw(n); onPick(n); } }, `${n} cifre`)));
  draw(current);
  return wrap;
}

// ── Clipboard with auto-clear ─────────────────────────────────
async function copy(text, label = 'Copiat') {
  try {
    await navigator.clipboard.writeText(text);
    const secs = S.data?.settings.clipClearSecs ?? 30;
    toast(secs ? `${label} · se șterge din clipboard în ${secs}s` : label);
    clearTimeout(S.timers.clip);
    S.clipPending = !!secs;
    if (secs) S.timers.clip = setTimeout(clearClipboard, secs * 1000);
  } catch { toast('Nu s-a putut copia', 'err'); }
}
async function clearClipboard() {
  if (!S.clipPending) return;
  try { await navigator.clipboard.writeText(''); S.clipPending = false; } catch { /* retried when focus returns */ }
}

// ── Session: auto-lock ─────────────────────────────────────────
function resetIdle() {
  clearTimeout(S.timers.idle);
  if (!S.key || S.holdLock) return;
  const m = S.data.settings.autoLockMins;
  if (m) S.timers.idle = setTimeout(() => lock('Blocat automat după inactivitate'), m * 60_000);
}
['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true, capture: true }));

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    document.body.classList.add('privacy');
    if (S.key && !S.external && !S.holdLock) {
      const secs = S.data.settings.hideLockSecs;
      if (secs === 0) lock();
      else if (secs > 0) S.timers.hide = setTimeout(() => lock('Blocat cât aplicația a fost în fundal'), secs * 1000);
    }
  } else {
    document.body.classList.remove('privacy');
    clearTimeout(S.timers.hide);
    // A cancelled file picker never fires 'change'; don't leave background-lock disabled.
    if (S.external === 'picker') S.external = false;
    clearClipboard();
  }
});
window.addEventListener('focus', clearClipboard);

function lock(msg) {
  S.key = null;
  S.data = null;
  S.holdLock = false;
  S.query = '';
  ['idle', 'hide', 'reveal'].forEach(t => clearTimeout(S.timers[t]));
  closeAllModals();
  clearClipboard();
  route();
  if (msg) toast('🔒 ' + msg, 'info', 2500);
}

// ── Persistence ────────────────────────────────────────────────
// Every vault write goes through one queue so concurrent saves never overwrite each other.
function enqueue(task) {
  const run = S.saving.then(task);
  S.saving = run.catch(() => {});
  return run;
}
// Re-encrypt the entries. Resolves true on success, false on failure (already reported).
function persist() {
  const key = S.key, data = S.data;
  return enqueue(async () => {
    if (!key || !S.record) return false;
    const box = await C.encryptPayload(key, data);
    const rec = { ...S.record, data: box, updated: Date.now() };
    await DB.set('vault', rec);
    S.record = rec;
    return true;
  }).catch(err => { console.error(err); toast('Eroare la salvare! Modificarea nu a fost păstrată.', 'err', 5000); return false; });
}
// Replace parts of the record (wraps, keys…). `patch` receives the latest record.
function saveRecord(patch) {
  return enqueue(async () => {
    const rec = typeof patch === 'function' ? patch(S.record) : patch;
    await DB.set('vault', rec);
    S.record = rec;
  });
}

// ── Attempt counter (meta) ─────────────────────────────────────
// Always read-modify-write from IndexedDB under a Web Lock, so no stale copy
// can reset the counter, the lock or a running self-destruct.
async function updateMeta(fn) {
  const work = async () => {
    const m = { ...DEFAULT_META, ...(await DB.get('meta') || {}) };
    fn(m);
    await DB.set('meta', m);
    S.meta = m;
    return m;
  };
  return navigator.locks ? navigator.locks.request('vault-meta', work) : work();
}
async function reloadMeta() { S.meta = { ...DEFAULT_META, ...(await DB.get('meta') || {}) }; }

function normalizeData(p) {
  return {
    entries: Array.isArray(p.entries) ? p.entries.map(cleanEntry).filter(Boolean) : [],
    settings: { ...DEFAULT_SETTINGS, ...(p.settings || {}) },
    created: p.created || Date.now(),
  };
}
const str = (v, max) => (typeof v === 'string' ? v : v == null ? '' : String(v)).slice(0, max);
function cleanEntry(e) {
  if (!e || typeof e !== 'object') return null;
  const out = {
    id: typeof e.id === 'string' && e.id ? e.id.slice(0, 64) : crypto.randomUUID(),
    site: str(e.site, 200).trim(),
    username: str(e.username ?? e.email, 300).trim(),
    password: str(e.password, 2000),
    url: str(e.url, 1000).trim(),
    notes: str(e.notes, 10000),
    created: Number(e.created) || Date.now(),
    updated: Number(e.updated) || Number(e.created) || Date.now(),
  };
  if (!out.site && !out.username) return null;
  if (!out.site) out.site = out.username.split('@')[1] || 'Fără nume';
  return out;
}

// ── Unlock ─────────────────────────────────────────────────────
async function openWithDek(dek) {
  let payload, key;
  try {
    key = await C.importDek(dek);
    payload = await C.decryptPayload(key, S.record.data);
  } catch (e) {
    // The DEK unwrapped fine, so this is corrupted data, not a wrong PIN.
    const err = new Error('data_corrupt'); err.cause = e; throw err;
  } finally { dek.fill(0); }
  S.key = key;
  S.data = normalizeData(payload);
  await updateMeta(m => { m.fails = 0; m.lockUntil = 0; m.destructAt = 0; });
  resetIdle();
  route();
}

const policy = () => ({ ...DEFAULT_POLICY, ...(S.meta.policy || {}) });

// An attempt is counted BEFORE it is verified, so killing the app mid-check
// cannot bypass the limit.
// Returns false if attempts are currently not allowed (locked / self-destruct running).
async function beginAttempt() {
  let allowed = true;
  await updateMeta(m => {
    if (m.destructAt || m.lockUntil > Date.now()) { allowed = false; return; }
    m.fails = (m.fails || 0) + 1;
  });
  if (!allowed) route();
  return allowed;
}
// A technical error (not a wrong PIN) must not cost an attempt.
const undoAttempt = () => updateMeta(m => { m.fails = Math.max(0, (m.fails || 0) - 1); });
async function failAttempt() {
  const pol = policy();
  const m = await updateMeta(m => {
    if (m.fails >= pol.wipeAfter) { if (!m.destructAt) m.destructAt = Date.now() + pol.countdown * 1000; }
    else if (m.fails >= LOCK_AFTER) m.lockUntil = Date.now() + LOCK_MS;
  });
  if (m.destructAt) { closeAllModals(); S.key = null; S.data = null; route(); return 'destruct'; }
}
// Shared PIN check used by login and by confirmations while unlocked.
// Returns the DEK, or throws: Error('wrong_pin' | 'blocked' | 'destruct' | 'argon_unavailable' | other).
async function verifyPin(pin, prf) {
  if (S.record.kdf.alg === 'argon2id' && !C.argonAvailable()) throw new Error('argon_unavailable');
  if (!(await beginAttempt())) throw new Error('blocked');
  let dek;
  try {
    const kek = await C.deviceKey(pin, prf, S.record.kdf);
    dek = await C.unwrapDev(kek, S.record.wraps.dev);
  } catch (e) {
    if (e?.name === 'OperationError') {
      if (await failAttempt() === 'destruct') throw new Error('destruct');
      throw new Error('wrong_pin');
    }
    await undoAttempt();
    throw e;
  }
  return dek;
}
function pinErrorText(err) {
  if (err.message === 'argon_unavailable') return 'Browserul blochează WebAssembly, necesar pentru criptare. Încearcă din Chrome, fără mod restricționat.';
  if (err.message === 'data_corrupt') return 'Datele seifului sunt deteriorate. Restaurează dintr-un backup.';
  if (err.name === 'NotAllowedError') return 'Amprenta a fost anulată';
  return 'Eroare: ' + (err.message || err);
}
// On startup: enforce the policy even if the app was closed in the meantime.
async function enforceAttemptPolicy() {
  if (!S.record) return;
  if (S.meta.destructAt && Date.now() >= S.meta.destructAt) return wipeAll('💥 Autodistrugere finalizată. Datele au fost șterse.');
  const pol = policy();
  await updateMeta(m => {
    if (m.fails >= pol.wipeAfter && !m.destructAt) m.destructAt = Date.now() + pol.countdown * 1000;
    else if (m.fails >= LOCK_AFTER && !m.lockUntil && !m.destructAt) m.lockUntil = Date.now() + LOCK_MS;
  });
}

async function wipeAll(msg = 'Seiful a fost șters') {
  const keepPolicy = S.meta.policy;
  await enqueue(() => DB.clear());
  S.record = null; S.key = null; S.data = null; S.pending = null; S.holdLock = false;
  if (PREVIEW) MockBio.save({});
  await updateMeta(m => { Object.assign(m, DEFAULT_META, { policy: keepPolicy }); });
  closeAllModals();
  route();
  toast(msg, 'err', 4500);
}

// ── Simulated fingerprint: preview page ONLY ─────────────────────
// The claude.ai preview runs in a sandboxed frame that blocks WebAuthn.
// That page carries <meta name="vault-preview">; the GitHub index.html does NOT,
// so in the real app this code path is never active.
const PREVIEW = !!document.querySelector('meta[name="vault-preview"]');
const MockBio = {
  key: '__vault_preview_bio',
  load() { try { return JSON.parse(localStorage.getItem(this.key) || '{}'); } catch { return {}; } },
  save(m) { try { localStorage.setItem(this.key, JSON.stringify(m)); } catch {} },
  async hmac(secret, salt) {
    const k = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, salt));
  },
  ask(title) {
    return new Promise((resolve, reject) => {
      const ov = modal('👆 ' + title, h('div', null,
        h('div', { class: 'info-box' }, 'Previzualizare: amprenta e simulată. Pe telefon, aici apare senzorul real.'),
        h('div', { class: 'mock-sensor', 'aria-hidden': 'true' }, '👆'),
        h('button', { class: 'btn btn-primary', onclick: () => { ov.close(); resolve(); } }, 'Atinge senzorul (amprenta mea)'),
        h('button', { class: 'btn btn-ghost mt8', onclick: () => { ov.close(); reject(new DOMException('cancelled', 'NotAllowedError')); } }, 'Anulează')));
      ov.classList.add('top');
      ov.onX = () => reject(new DOMException('cancelled', 'NotAllowedError'));
    });
  },
  async enroll(prfSalt) {
    await this.ask('Înregistrează amprenta');
    const id = C.rand(16), secret = C.rand(32);
    const m = this.load(); m[C.b64(id)] = C.b64(secret); this.save(m);
    return { credId: id, first: await this.hmac(secret, prfSalt) };
  },
  async get(credId, prfSalt) {
    await this.ask('Confirmă cu amprenta');
    const sec = this.load()[C.b64(credId)];
    if (!sec) throw new DOMException('unknown credential', 'NotAllowedError');
    return this.hmac(C.unb64(sec), prfSalt);
  },
};

// ── Fingerprint (WebAuthn PRF) ───────────────────────────────────
// The fingerprint releases a secret held by the phone (passkey PRF output).
// That secret + the PIN derive the key that opens the vault.
const Bio = {
  async supported() {
    if (PREVIEW) return true;
    try {
      return !!(window.PublicKeyCredential && navigator.credentials &&
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
    } catch { return false; }
  },
  async enroll() {
    const prfSalt = C.rand(32);
    S.external = true;
    try {
      if (PREVIEW) {
        const { credId, first } = await MockBio.enroll(prfSalt);
        return { bio: { credId: C.b64(credId), prfSalt: C.b64(prfSalt), check: await C.bioCheck(first) }, secret: first };
      }
      const cred = await navigator.credentials.create({ publicKey: {
        rp: { name: 'Vault', id: location.hostname },
        user: { id: C.rand(16), name: 'Vault', displayName: 'Vault — seif parole' },
        challenge: C.rand(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        timeout: 60_000,
        extensions: { prf: { eval: { first: prfSalt } } },
      } });
      const ext = cred.getClientExtensionResults()?.prf;
      if (!ext || ext.enabled === false) throw new Error('prf_unsupported');
      const credId = new Uint8Array(cred.rawId);
      const secret = ext.results?.first ? new Uint8Array(ext.results.first) : await Bio.secretRaw(credId, prfSalt);
      return { bio: { credId: C.b64(credId), prfSalt: C.b64(prfSalt), check: await C.bioCheck(secret) }, secret };
    } finally { S.external = false; }
  },
  async secretRaw(credId, prfSalt) {
    if (PREVIEW) return MockBio.get(credId, prfSalt);
    const a = await navigator.credentials.get({ publicKey: {
      challenge: C.rand(32), rpId: location.hostname,
      allowCredentials: [{ type: 'public-key', id: credId }],
      userVerification: 'required', timeout: 60_000,
      extensions: { prf: { eval: { first: prfSalt } } },
    } });
    const r = a.getClientExtensionResults()?.prf?.results?.first;
    if (!r) throw new Error('prf_unsupported');
    return new Uint8Array(r);
  },
  // Ask for the fingerprint of the current vault; returns the secret or throws.
  async secret(bio = S.record?.bio) {
    S.external = true;
    try {
      const s = await Bio.secretRaw(C.unb64(bio.credId), C.unb64(bio.prfSalt));
      if (await C.bioCheck(s) !== bio.check) throw new Error('bio_mismatch');
      return s;
    } finally { S.external = false; }
  },
};

// Ask for PIN (+ fingerprint) and return { dek, pin, prf } for sensitive actions while unlocked.
function askAuth(title, onOk, note) {
  const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, S.record.bio ? 'Confirmă cu amprenta →' : 'Confirmă');
  const pin = pinField(S.record.pinLen, { onComplete: () => form.requestSubmit() });
  let working = false;
  const form = h('form', { onsubmit: async e => {
    e.preventDefault();
    if (working || pin.input.value.length !== S.record.pinLen) return;
    working = true;
    const done = busy(btn, 'Se verifică…');
    let prf = null, dek;
    try {
      if (S.record.bio) prf = await Bio.secret();
      dek = await verifyPin(pin.input.value, prf); // wrong PINs count here too
      await updateMeta(m => { m.fails = 0; m.lockUntil = 0; });
    } catch (err) {
      prf?.fill(0);
      working = false; done();
      if (err.message === 'destruct' || err.message === 'blocked') { ov.close(); return route(); }
      if (err.message === 'wrong_pin') {
        pin.error();
        const left = policy().wipeAfter - S.meta.fails;
        return toast(`PIN greșit. Mai ai ${left} ${left === 1 ? 'încercare' : 'încercări'} până la autodistrugere.`, 'err', 3500);
      }
      if (err.name !== 'NotAllowedError') console.error(err);
      return toast(pinErrorText(err), err.name === 'NotAllowedError' ? 'info' : 'err', 4000);
    }
    ov.close();
    try { await onOk({ dek, pin: pin.input.value, prf }); }
    catch (err) { console.error(err); toast(pinErrorText(err), 'err', 4000); }
    finally { prf?.fill(0); }
  } }, note && h('div', { class: 'info-box' }, note), field('PIN-ul aplicației', pin), btn,
     h('button', { class: 'btn btn-ghost mt8', type: 'button', onclick: () => ov.close() }, 'Anulează'));
  const ov = modal(title, form);
}

// ════════════════════════════════════════════════════════════════
// SCREENS
// ════════════════════════════════════════════════════════════════
function route() {
  document.body.classList.remove('destruct-mode');
  clearInterval(S.timers.countdown);
  clearInterval(S.timers.destruct);
  if (!S.record) return showWelcome();
  if (S.record.v !== 5) return showOldVersion();
  if (S.meta.destructAt) return showDestruct();
  if (!S.key) return showLogin();
  showApp();
}

function lockVisual(icon, title, subtitle) {
  return h('div', { class: 'lock-visual' },
    h('span', { class: 'lock-icon' }, icon),
    h('div', { class: 'lock-title' }, title),
    subtitle && h('div', { class: 'lock-subtitle' }, subtitle));
}
function steps(n, total) {
  if (!total) return null;
  return h('div', { class: 'steps', 'aria-label': `Pasul ${n} din ${total}` },
    Array.from({ length: total }, (_, i) => h('span', { class: i < n ? 'on' : '' })));
}

function showOldVersion() {
  mount(h('div', { class: 'card' },
    lockVisual('⚠️', 'Seif dintr-o versiune de test', 'Formatul s-a schimbat. Șterge-l și creează unul nou.'),
    h('button', { class: 'btn btn-danger', onclick: () => wipeAll('Seiful vechi a fost șters') }, 'Șterge și începe din nou')));
}

// ── Welcome ──────────────────────────────────────────────────
function showWelcome() {
  mount(h('div', { class: 'card' },
    lockVisual('🔐', 'Bun venit', 'Parolele tale, criptate doar pe acest telefon'),
    h('button', { class: 'btn btn-primary', onclick: () => setupPin({ mode: 'new' }) }, 'Creează un seif nou'),
    h('button', { class: 'btn btn-ghost mt8', onclick: showRestore }, '📥 Restaurează dintr-un backup')));
}

// ── Step 1: PIN ───────────────────────────────────────────────
function setupPin(ctx) {
  let len = ctx.pinLen || 6;
  const total = ctx.mode === 'new' ? 4 : 3;
  const btn = h('button', { class: 'btn btn-primary mt8', type: 'submit' }, 'Continuă →');
  const pin = pinField(len, { placeholder: 'PIN nou' });
  const pin2 = pinField(len, { placeholder: 'Repetă PIN-ul' });
  pin2.querySelector('.pin-display')?.remove();
  mount(h('div', { class: 'card' },
    steps(ctx.mode === 'new' ? 1 : 2, total),
    lockVisual('🔢', ctx.mode === 'new' ? 'Alege PIN-ul' : 'PIN pentru acest telefon',
      ctx.mode === 'restore' ? 'Poate fi același ca înainte sau unul nou' : 'Cu el deschizi aplicația, împreună cu amprenta'),
    h('div', { class: 'section-label' }, 'Lungime PIN'),
    lengthPicker(len, n => { len = n; pin.setLen(n); pin2.setLen(n); pin.input.focus(); }),
    h('form', { onsubmit: e => {
      e.preventDefault();
      const err = checkPin(pin.input.value, pin2.input.value, len);
      if (err) { pin.error(); pin2.error(); return toast(err, 'err', 3500); }
      setupBio({ ...ctx, pin: pin.input.value, pinLen: len, total });
    } }, field(null, pin), field(null, pin2), btn),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => { ctx.seed?.fill(0); route(); } }, '← Înapoi')));
  autoFocus(() => pin.input);
}

// ── Step 2: fingerprint────────────────────────────────────────
async function setupBio(ctx) {
  const supported = await Bio.supported();
  const finish = async (bio, secret) => {
    mount(h('div', { class: 'card' }, lockVisual('⏳', 'Se creează seiful…', 'Câteva secunde')));
    let built;
    try { built = await buildVault(ctx, bio, secret); }
    catch (e) { console.error(e); toast(pinErrorText(e), 'err', 5000); return setupBio(ctx); }
    finally { secret?.fill(0); }
    if (ctx.mode === 'restore') {
      ctx.seed.fill(0);
      try { await commitVault(built); } catch (e) { console.error(e); toast('Eroare la salvare: ' + e.message, 'err', 5000); return setupBio(ctx); }
      route();
      return toast(`✓ Restaurat: ${S.data.entries.length} intrări`);
    }
    // New vault: nothing is saved until the words have been written down and checked.
    S.pending = built;
    showWords(ctx.seed, async () => {
      const b = S.pending; S.pending = null;
      await commitVault(b);
      route();
      toast('✓ Seiful e gata');
    }, ctx.total);
  };
  const enrollBtn = h('button', { class: 'btn btn-primary', disabled: !supported, onclick: async () => {
    const done = busy(enrollBtn, 'Pune degetul pe senzor…');
    try {
      const { bio, secret } = await Bio.enroll();
      await finish(bio, secret);
    } catch (e) {
      done(); console.error(e);
      toast(e.message === 'prf_unsupported' ? 'Telefonul nu suportă amprenta pentru criptare' : 'Amprenta a fost anulată', 'err', 4000);
      skipBtn.hidden = false; // after a failure, allow continuing with PIN only
    }
  } }, '👆 Înregistrează amprenta');
  const skipBtn = h('button', { class: 'btn btn-ghost mt8', onclick: () => finish(null, null) }, 'Continuă doar cu PIN');
  skipBtn.hidden = supported;
  mount(h('div', { class: 'card' },
    steps(ctx.mode === 'new' ? 2 : 3, ctx.total),
    lockVisual('👆', 'Amprenta', 'La fiecare deschidere vei pune PIN-ul și amprenta'),
    PREVIEW && h('div', { class: 'info-box' }, h('strong', null, 'Previzualizare: '), 'amprenta e simulată cu un buton. Pe telefon vei folosi senzorul real.'),
    supported
      ? !PREVIEW && h('div', { class: 'info-box' }, 'Android îți va cere să salvezi o „cheie de acces” pentru Vault. Acceptă și confirmă cu amprenta. Cheia rămâne în telefonul tău.')
      : h('div', { class: 'info-box warn' }, h('strong', null, 'Amprenta nu e disponibilă aici. '),
          'Pe GitHub Pages, în Chrome pe Android, va funcționa. Poți continua doar cu PIN și activa amprenta mai târziu din Setări.'),
    enrollBtn,
    skipBtn,
    h('button', { class: 'btn btn-ghost mt8', onclick: () => setupPin(ctx) }, '← Înapoi')));
}

// Build the encrypted vault in memory (nothing is written yet).
async function buildVault(ctx, bio, prf) {
  const dek = C.rand(32);
  const seed = ctx.seed || C.rand(32);
  ctx.seed = seed;
  try {
    const kdf = { ...C.defaultKdf(), salt: C.b64(C.rand(16)) };
    const kek = await C.deviceKey(ctx.pin, prf, kdf);
    const rec = {
      v: 5, created: Date.now(), pinLen: ctx.pinLen, kdf, bio: bio || null,
      wraps: { dev: await C.wrapDev(kek, dek), rk: await C.wrapRecovery(dek, seed) },
      backup: await C.makeBackupKeys(seed),
    };
    const key = await C.importDek(dek);
    const data = normalizeData({ entries: ctx.entries || [], settings: ctx.settings || DEFAULT_SETTINGS, created: Date.now() });
    rec.data = await C.encryptPayload(key, data);
    return { rec, key, data };
  } finally { dek.fill(0); }
}
async function commitVault({ rec, key, data }) {
  await saveRecord(rec);
  await updateMeta(m => { m.fails = 0; m.lockUntil = 0; m.destructAt = 0; });
  S.key = key; S.data = data;
  resetIdle();
}

// ── Steps 3–4: the 24 words + quiz ────────────────────────────
async function showWords(seed, onDone, total = 4) {
  const words = await C.seedToWords(seed);
  seed.fill(0);
  S.holdLock = true; // don't auto-lock while the user is writing the words down
  clearTimeout(S.timers.idle);
  const grid = h('ol', { class: 'words' }, words.map(w => h('li', null, h('span', null, w))));
  mount(h('div', { class: 'card' },
    steps(3, total),
    lockVisual('🗝', 'Cele 24 de cuvinte', 'Cheia backup-urilor tale'),
    h('div', { class: 'info-box warn' },
      h('strong', null, 'Scrie-le pe hârtie, în ordine. '),
      'Fără ele, backup-urile nu pot fi deschise de nimeni, nici de tine. Nu le fotografia, nu le salva în telefon sau în Drive. Nu vor mai fi afișate.'),
    grid,
    h('button', { class: 'btn btn-primary mt12', onclick: () => quizWords(words, onDone, total) }, 'Le-am scris →')));
}

function quizWords(words, onDone, total) {
  const pos = [];
  while (pos.length < 3) { const p = C.randInt(24); if (!pos.includes(p)) pos.push(p); }
  pos.sort((a, b) => a - b);
  const inputs = pos.map(p => textInput({ placeholder: `Cuvântul nr. ${p + 1}`, autocomplete: 'off' }));
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Verifică →');
  mount(h('div', { class: 'card' },
    steps(4, total),
    lockVisual('✍️', 'Verificare', 'Scrie cuvintele cerute, din foaia ta'),
    h('form', { onsubmit: async e => {
      e.preventDefault();
      if (submit.disabled) return;
      const ok = pos.every((p, i) => inputs[i].value.trim().toLowerCase() === words[p]);
      if (!ok) return toast('Unul dintre cuvinte nu se potrivește. Verifică foaia.', 'err', 3500);
      const done = busy(submit, 'Se salvează…');
      try {
        await onDone();
        words.fill('');
        S.holdLock = false;
        resetIdle();
      } catch (err) { console.error(err); done(); toast('Eroare la salvare: ' + err.message, 'err', 5000); }
    } }, pos.map((p, i) => field(`Cuvântul nr. ${p + 1}`, inputs[i])),
      submit),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => {
      const grid = h('ol', { class: 'words' }, words.map(w => h('li', null, h('span', null, w))));
      const ov = modal('🗝 Cele 24 de cuvinte', h('div', null, grid, h('button', { class: 'btn btn-ghost mt12', onclick: () => ov.close() }, 'Închide')));
    } }, 'Arată-mi din nou cuvintele')));
  autoFocus(() => inputs[0]);
}

// ── Restore on a new phone ───────────────────────────────────
function wordsArea(id) {
  const ta = h('textarea', { id, rows: 4, class: 'mono', placeholder: 'cele 24 de cuvinte, separate prin spațiu', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false' });
  return ta;
}
function wordsError(e) {
  if (e.message === 'bad_length') return `Trebuie exact 24 de cuvinte (ai scris ${e.count}).`;
  if (e.message === 'bad_word') return `„${e.word}” nu e un cuvânt valid din listă.`;
  if (e.message === 'bad_checksum') return 'Cuvintele nu formează o cheie validă. Verifică ordinea și ortografia.';
  return 'Cuvinte invalide.';
}

function showRestore() {
  let file = null;
  const fileLabel = h('div', { class: 'hint' }, 'Niciun fișier ales');
  const loadText = text => {
    try {
      const j = JSON.parse(text.trim());
      if (!C.validBackup(j)) throw new Error();
      file = j;
      fileLabel.textContent = `✓ Backup din ${fmtDate(j.created)} · PIN de ${j.pinLen} cifre`;
      pin.setLen(j.pinLen);
    } catch { file = null; fileLabel.textContent = text.trim() ? 'Nu e un backup Vault valid.' : 'Niciun fișier ales'; }
  };
  const fileIn = h('input', { type: 'file', accept: '.txt,.json,text/plain,application/json', class: 'hidden', onchange: async e => {
    S.external = false;
    const f = e.target.files[0]; e.target.value = '';
    if (f) loadText(await f.text());
  } });
  const pasteTa = h('textarea', { id: 'rpaste', class: 'mono backup-text', rows: 3, placeholder: 'sau lipește aici textul backup-ului', spellcheck: 'false' });
  pasteTa.addEventListener('input', () => loadText(pasteTa.value));
  const ta = wordsArea('rwords');
  const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Deschide backup-ul →');
  const pin = pinField(6, { placeholder: 'PIN-ul vechi' });
  mount(h('div', { class: 'card' },
    steps(1, 3),
    lockVisual('📥', 'Restaurare', 'Ai nevoie de: fișierul de backup, cele 24 de cuvinte și PIN-ul de atunci'),
    h('form', { onsubmit: async e => {
      e.preventDefault();
      if (!file) return toast('Alege mai întâi fișierul de backup', 'err');
      let seed;
      try { seed = await C.wordsToSeed(ta.value); } catch (er) { return toast(wordsError(er), 'err', 4000); }
      if (!(await C.checkBackupWords(file, seed))) return toast('Cuvintele sunt valide, dar nu sunt cheia acestui backup.', 'err', 4000);
      if (pin.input.value.length !== file.pinLen) return pin.error();
      const done = busy(btn, 'Se decriptează…');
      try {
        const data = await C.openBackup(file, seed, pin.input.value);
        setupPin({ mode: 'restore', seed, entries: (data.entries || []).map(cleanEntry).filter(Boolean), settings: data.settings, pinLen: file.pinLen });
      } catch (er) { done(); seed.fill(0); pin.error(); toast(er?.name === 'OperationError' ? 'PIN greșit pentru acest backup' : 'Eroare: ' + er.message, 'err'); }
    } },
      field('1. Fișierul de backup', h('div', null,
        h('button', { class: 'btn btn-ghost', type: 'button', onclick: () => { S.external = 'picker'; fileIn.click(); } }, '📄 Alege fișierul'), fileIn,
        h('div', { class: 'mt8' }, pasteTa), fileLabel)),
      field('2. Cele 24 de cuvinte', ta),
      field('3. PIN-ul vechi', pin),
      btn),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => route() }, '← Înapoi')));
}

// ── Login ──────────────────────────────────────────────────────
function showLogin() {
  const len = S.record.pinLen;
  const hasBio = !!S.record.bio;
  const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, hasBio ? 'Deblochează cu amprenta →' : 'Deblochează →');
  const pin = pinField(len, { onComplete: () => form.requestSubmit() });
  const warn = h('div', { class: 'warn-line' });
  let working = false;

  const updateLock = () => {
    const fails = S.meta.fails - (working ? 1 : 0);
    const rem = S.meta.lockUntil - Date.now();
    const locked = rem > 0;
    btn.disabled = locked || working;
    pin.input.disabled = locked;
    const left = policy().wipeAfter - fails;
    if (locked) {
      const m = Math.floor(rem / 60000), s = Math.floor((rem % 60000) / 1000);
      warn.textContent = `⏳ Aplicație blocată. Reîncearcă peste ${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}. Mai ai ${left} ${left === 1 ? 'încercare' : 'încercări'} până la autodistrugere.`;
    } else if (fails > 0) {
      warn.textContent = left === 1
        ? '⚠️ Ultima încercare. Un PIN greșit pornește autodistrugerea.'
        : `⚠️ PIN greșit. Mai ai ${left} încercări până la autodistrugere` + (fails < LOCK_AFTER ? ` (blocare după ${LOCK_AFTER}).` : '.');
    } else warn.textContent = '';
  };
  updateLock();
  S.timers.countdown = setInterval(updateLock, 1000);
  reloadMeta().then(() => { if (S.meta.destructAt) route(); else updateLock(); });

  const form = h('form', { onsubmit: async e => {
    e.preventDefault();
    if (working || S.meta.lockUntil > Date.now() || pin.input.value.length !== len) return;
    working = true;
    const done = busy(btn, hasBio ? 'Pune degetul pe senzor…' : 'Se deblochează…');
    let prf = null;
    try {
      if (hasBio) prf = await Bio.secret(); // a cancelled fingerprint does NOT count as a wrong PIN
    } catch (err) {
      working = false; done();
      return toast(err?.name === 'NotAllowedError' ? 'Amprenta a fost anulată' : 'Amprenta nu a fost recunoscută', 'info');
    }
    btn.textContent = 'Se deblochează…';
    try {
      await openWithDek(await verifyPin(pin.input.value, prf));
    } catch (err) {
      working = false; done();
      if (err.message === 'destruct' || err.message === 'blocked') return route();
      if (err.message !== 'wrong_pin') { console.error(err); return toast(pinErrorText(err), 'err', 5000); }
      pin.error();
      const card = form.closest('.card');
      card?.classList.add('shake'); setTimeout(() => card?.classList.remove('shake'), 500);
      updateLock();
      toast(S.meta.lockUntil > Date.now() ? `🔒 Blocat ${LOCK_MS / 60000} minute` : 'PIN greșit', 'err');
    } finally { prf?.fill(0); }
  } }, field(null, pin), warn, btn);

  mount(h('div', { class: 'card' },
    lockVisual('🔒', 'Deblochează seiful', hasBio ? `PIN de ${len} cifre + amprentă` : `PIN de ${len} cifre`),
    form,
    h('button', { class: 'btn btn-ghost mt8 small', type: 'button', onclick: showRecoverFlow }, '🗝 Am uitat PIN-ul — folosește cele 24 de cuvinte'),
    h('div', { class: 'footer-zone' },
      h('button', { class: 'btn btn-danger btn-sm', type: 'button', onclick: confirmWipe }, '💀 Șterge seiful și începe din nou'))));
  autoFocus(() => pin.input);
}

// ── Self-destruct countdown ───────────────────────────────────
function showDestruct() {
  const hasBio = !!S.record.bio;
  const timer = h('div', { class: 'destruct-timer' }, '--');
  const bar = h('div', { class: 'destruct-bar-fill' });
  const total = policy().countdown * 1000;
  const tick = () => {
    const rem = Math.max(0, S.meta.destructAt - Date.now());
    timer.textContent = String(Math.ceil(rem / 1000));
    bar.style.width = (rem / total * 100) + '%';
    if (rem <= 0) { clearInterval(S.timers.destruct); wipeAll('💥 Autodistrugere finalizată. Datele au fost șterse.'); }
    else if (Math.ceil(rem / 1000) !== tick.last) { tick.last = Math.ceil(rem / 1000); try { if (navigator.userActivation?.hasBeenActive) navigator.vibrate?.(120); } catch {} }
  };
  const abort = h('button', { class: 'btn btn-primary', disabled: !hasBio, onclick: async () => {
    const done = busy(abort, 'Pune degetul pe senzor…');
    try {
      const s = await Bio.secret(); s.fill(0);
      await updateMeta(m => { m.fails = 0; m.lockUntil = 0; m.destructAt = 0; });
      route();
      toast('✓ Autodistrugere anulată', 'ok', 3000);
    } catch { done(); toast('Amprenta nu a fost recunoscută', 'err'); }
  } }, '👆 Anulează cu amprenta');
  document.body.classList.add('destruct-mode');
  mount(h('div', { class: 'card destruct' },
    lockVisual('💥', 'Autodistrugere', `${S.meta.fails} PIN-uri greșite`),
    timer,
    h('div', { class: 'destruct-bar' }, bar),
    h('p', { class: 'destruct-text' }, 'Când timpul expiră, toate datele de pe acest telefon se șterg definitiv. Ele pot fi readuse doar dintr-un backup, cu cele 24 de cuvinte.'),
    hasBio ? abort : h('div', { class: 'info-box warn' }, 'Seiful nu are amprentă activată, deci autodistrugerea nu poate fi oprită.')));
  tick();
  S.timers.destruct = setInterval(tick, 200);
}

function showRecoverFlow() {
  const ta = wordsArea('kwords');
  const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Verifică →');
  const ov = modal('🗝 Am uitat PIN-ul', h('form', { onsubmit: async e => {
    e.preventDefault();
    let seed;
    try { seed = await C.wordsToSeed(ta.value); } catch (er) { return toast(wordsError(er), 'err', 4000); }
    const done = busy(btn, 'Se verifică…');
    try {
      const dek = await C.unwrapRecovery(S.record.wraps.rk, seed);
      seed.fill(0);
      ov.close();
      setNewPinAfterRecovery(dek);
    } catch { seed.fill(0); done(); toast('Cuvintele nu sunt cheia acestui seif', 'err'); }
  } },
    h('div', { class: 'info-box' }, 'Scrie cele 24 de cuvinte. Apoi vei alege un PIN nou' + (S.record.bio ? ' și vei confirma cu amprenta.' : '.')),
    field('Cele 24 de cuvinte', ta), btn,
    h('button', { class: 'btn btn-ghost mt8', type: 'button', onclick: () => ov.close() }, 'Anulează')));
}

function setNewPinAfterRecovery(dek) {
  let len = S.record.pinLen;
  const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Salvează și deblochează');
  const pin = pinField(len, { placeholder: 'PIN nou' });
  const pin2 = pinField(len, { placeholder: 'Repetă PIN-ul' });
  pin2.querySelector('.pin-display')?.remove();
  const ov = modal('🔑 PIN nou', h('form', { onsubmit: async e => {
    e.preventDefault();
    const err = checkPin(pin.input.value, pin2.input.value, len);
    if (err) { pin.error(); pin2.error(); return toast(err, 'err', 3500); }
    const done = busy(btn, S.record.bio ? 'Pune degetul pe senzor…' : 'Se salvează…');
    let prf = null;
    try {
      if (S.record.bio) prf = await Bio.secret();
      const kdf = { ...C.defaultKdf(), salt: C.b64(C.rand(16)) };
      const dev = await C.wrapDev(await C.deviceKey(pin.input.value, prf, kdf), dek);
      await saveRecord(r => ({ ...r, pinLen: len, kdf, wraps: { ...r.wraps, dev } }));
      ov.onX = null;
      ov.close();
      await openWithDek(dek);
      toast('✓ PIN-ul a fost schimbat');
    } catch (e2) { console.error(e2); done(); toast(pinErrorText(e2), 'err', 4000); }
    finally { prf?.fill(0); }
  } }, lengthPicker(len, n => { len = n; pin.setLen(n); pin2.setLen(n); }), field(null, pin), field(null, pin2), btn));
  ov.onX = () => dek.fill(0);
}

function confirmWipe() {
  const inp = textInput({ placeholder: 'ȘTERGE' });
  const ov = modal('💀 Ștergere completă', h('div', null,
    h('p', { class: 'muted mb12' }, 'Toate parolele și setările vor fi șterse DEFINITIV de pe acest telefon. Le poți readuce doar dintr-un backup, cu cele 24 de cuvinte.'),
    field('Scrie ȘTERGE pentru a confirma', inp),
    h('div', { class: 'row' },
      h('button', { class: 'btn btn-danger', onclick: async () => {
        const v = inp.value.trim().toUpperCase();
        if (v !== 'ȘTERGE' && v !== 'STERGE') return toast('Scrie exact: ȘTERGE', 'err');
        ov.close(); await wipeAll();
      } }, 'Șterge definitiv'),
      h('button', { class: 'btn btn-ghost', onclick: () => ov.close() }, 'Anulează'))), { danger: true });
}

// ── Main screen ──────────────────────────────────────────────────
function showApp() {
  const list = h('div', { id: 'entriesList' });
  const badge = h('span', { class: 'badge' });
  const search = textInput({ type: 'search', placeholder: 'Caută după site, utilizator sau URL…', value: S.query, 'aria-label': 'Caută' });
  search.addEventListener('input', () => { S.query = search.value; renderEntries(list, badge); });

  mount(
    h('div', { class: 'topbar' },
      h('div', null, h('div', { class: 'topbar-title' }, 'Seiful meu'), badge),
      h('div', { class: 'topbar-actions' },
        h('button', { class: 'btn btn-ghost btn-icon', title: 'Adaugă', 'aria-label': 'Adaugă', onclick: () => showEntryModal(null) }, '＋'),
        h('button', { class: 'btn btn-ghost btn-icon', title: 'Generator', 'aria-label': 'Generator', onclick: () => showGenerator() }, '🎲'),
        h('button', { class: 'btn btn-ghost btn-icon', title: 'Export backup criptat', 'aria-label': 'Export backup criptat', onclick: () => doBackup() }, '📤'),
        h('button', { class: 'btn btn-ghost btn-icon', title: 'Setări', 'aria-label': 'Setări', onclick: showSettings }, '⚙'),
        h('button', { class: 'btn btn-ghost btn-icon', title: 'Blochează', 'aria-label': 'Blochează', onclick: () => lock() }, '🔒'))),
    h('div', { class: 'search-wrap' }, h('span', { class: 'search-icon' }, '🔍'), search),
    list);
  renderEntries(list, badge);
}

function refreshApp() {
  const list = document.getElementById('entriesList');
  if (list) renderEntries(list, document.querySelector('.topbar .badge'));
}

function renderEntries(list, badge) {
  const n = S.data.entries.length;
  if (badge) badge.textContent = `${n} ${n === 1 ? 'intrare' : 'intrări'}`;
  const q = S.query.trim().toLowerCase();
  const shown = S.data.entries
    .filter(e => !q || e.site.toLowerCase().includes(q) || e.username.toLowerCase().includes(q) || e.url.toLowerCase().includes(q))
    .sort((a, b) => a.site.localeCompare(b.site, 'ro', { sensitivity: 'base' }));

  if (!shown.length) {
    list.replaceChildren(h('div', { class: 'empty' },
      h('div', { class: 'empty-icon' }, q ? '🔍' : '🗝️'),
      h('p', null, q ? `Niciun rezultat pentru „${S.query}”` : 'Nicio parolă salvată. Apasă ＋ ca să adaugi una.')));
    return;
  }
  list.replaceChildren(...shown.map(e => h('div', { class: 'entry-card' },
    h('button', { class: 'entry-main', onclick: () => showDetail(e.id), 'aria-label': 'Detalii ' + e.site },
      h('div', { class: 'entry-avatar' }, (e.site.trim()[0] || '?').toUpperCase()),
      h('div', { class: 'entry-info' },
        h('div', { class: 'entry-site' }, e.site),
        h('div', { class: 'entry-user' }, e.username || '—'))),
    h('div', { class: 'entry-actions' },
      e.username && h('button', { class: 'btn btn-ghost btn-icon', title: 'Copiază utilizator', 'aria-label': 'Copiază utilizator', onclick: () => copy(e.username, 'Utilizator copiat') }, '👤'),
      h('button', { class: 'btn btn-ghost btn-icon', title: 'Copiază parola', 'aria-label': 'Copiază parola', onclick: () => copy(e.password, 'Parolă copiată') }, '🔑')))));
}

// ── Entry details ────────────────────────────────────────────
function safeUrl(u) {
  if (!u) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(u) ? u : 'https://' + u);
    return /^https?:$/.test(url.protocol) ? url.href : null;
  } catch { return null; }
}

function showDetail(id) {
  const e = S.data.entries.find(x => x.id === id);
  if (!e) return;
  const pwVal = h('div', { class: 'detail-value mono masked' }, '••••••••••••');
  let shown = false;
  const toggle = h('button', { class: 'btn btn-ghost btn-icon', 'aria-label': 'Arată parola', onclick: () => {
    shown = !shown;
    pwVal.textContent = shown ? e.password : '••••••••••••';
    pwVal.classList.toggle('masked', !shown);
    toggle.textContent = shown ? '🙈' : '👁';
    clearTimeout(S.timers.reveal);
    if (shown) S.timers.reveal = setTimeout(() => { if (shown) toggle.click(); }, 15_000);
  } }, '👁');
  const href = safeUrl(e.url);

  const row = (label, valueNode, ...actions) => h('div', { class: 'detail-row' },
    h('div', { class: 'detail-label' }, label),
    h('div', { class: 'detail-line' }, valueNode, h('div', { class: 'detail-actions' }, ...actions)));

  const ov = modal(e.site, h('div', null,
    e.username && row('Utilizator / email', h('div', { class: 'detail-value mono' }, e.username),
      h('button', { class: 'btn btn-ghost btn-icon', 'aria-label': 'Copiază', onclick: () => copy(e.username, 'Utilizator copiat') }, '📋')),
    row('Parolă', pwVal, toggle,
      h('button', { class: 'btn btn-ghost btn-icon', 'aria-label': 'Copiază', onclick: () => copy(e.password, 'Parolă copiată') }, '📋')),
    e.url && row('Adresă', href
      ? h('a', { class: 'detail-value link', href, target: '_blank', rel: 'noopener noreferrer' }, e.url)
      : h('div', { class: 'detail-value' }, e.url)),
    e.notes && row('Notițe', h('div', { class: 'detail-value notes' }, e.notes)),
    h('div', { class: 'meta-line' }, `Creat: ${fmtDate(e.created)} · Modificat: ${fmtDate(e.updated)}`),
    h('div', { class: 'row mt12' },
      h('button', { class: 'btn btn-primary', onclick: () => { ov.close(); showEntryModal(e); } }, '✏️ Editează'),
      h('button', { class: 'btn btn-danger', onclick: () => { ov.close(); confirmDelete(e); } }, '🗑 Șterge')),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => ov.close() }, 'Închide')));
}

// ── Add / edit ──────────────────────────────────────────────
function showEntryModal(entry) {
  const isEdit = !!entry;
  const site = textInput({ placeholder: 'ex. Gmail, Instagram, Banca…', value: entry?.site, maxlength: 200, autocapitalize: 'words' });
  const user = textInput({ placeholder: 'email@exemplu.com', value: entry?.username, maxlength: 300, inputmode: 'email' });
  const pw = pwInput({ placeholder: 'Parola', value: entry?.password, maxlength: 2000 });
  const url = textInput({ placeholder: 'https://… (opțional)', value: entry?.url, maxlength: 1000, inputmode: 'url' });
  const notes = h('textarea', { placeholder: 'Notițe (opțional) — criptate și ele', maxlength: 10000, rows: 3, spellcheck: 'false' });
  notes.value = entry?.notes || '';
  const meter = strengthMeter(pw.input);
  const warn = h('div', { class: 'warn-line' });

  const ov = modal(isEdit ? '✏️ Editează' : '➕ Intrare nouă', h('form', { onsubmit: async ev => {
    ev.preventDefault();
    const s = site.value.trim(), u = user.value.trim(), p = pw.input.value;
    if (!s || !p) return toast('Completează site-ul și parola', 'err');
    const dup = S.data.entries.find(x => x.site.toLowerCase() === s.toLowerCase() && x.username.toLowerCase() === u.toLowerCase() && x.id !== entry?.id);
    if (dup && !warn.dataset.ok) {
      warn.textContent = `⚠️ Există deja „${s}” cu acest utilizator. Apasă din nou Salvează ca să păstrezi ambele.`;
      warn.dataset.ok = '1';
      return;
    }
    const now = Date.now();
    const vals = { site: s, username: u, password: p, url: url.value.trim(), notes: notes.value, updated: now };
    if (isEdit) {
      const i = S.data.entries.findIndex(x => x.id === entry.id);
      if (i !== -1) S.data.entries[i] = { ...S.data.entries[i], ...vals };
    } else {
      S.data.entries.push({ id: crypto.randomUUID(), created: now, ...vals });
    }
    if (!(await persist())) return;
    ov.close();
    refreshApp();
    toast(isEdit ? '✓ Actualizat' : '✓ Salvat');
  } },
    field('Site / aplicație *', site),
    field('Utilizator / email', user),
    field('Parolă *', pw), meter,
    h('button', { class: 'btn btn-ghost btn-sm mt8', type: 'button', onclick: () => {
      pw.input.value = C.generatePassword(S.gen);
      pw.input.type = 'text';
      meter.update();
    } }, '🎲 Generează parolă puternică'),
    field('Adresă web', url),
    field('Notițe', notes),
    warn,
    h('div', { class: 'row mt8' },
      h('button', { class: 'btn btn-primary', type: 'submit' }, '💾 Salvează'),
      h('button', { class: 'btn btn-ghost', type: 'button', onclick: () => ov.close() }, 'Anulează'))));
}

function confirmDelete(e) {
  const ov = modal('🗑 Confirmă ștergerea', h('div', null,
    h('p', { class: 'muted mb12' }, 'Ștergi definitiv parola pentru ', h('strong', null, e.site), e.username ? ` (${e.username})` : '', '?'),
    h('div', { class: 'row' },
      h('button', { class: 'btn btn-danger', onclick: async () => {
        S.data.entries = S.data.entries.filter(x => x.id !== e.id);
        if (!(await persist())) return;
        ov.close(); refreshApp(); toast('🗑 Șters');
      } }, 'Da, șterge'),
      h('button', { class: 'btn btn-ghost', onclick: () => ov.close() }, 'Anulează'))), { danger: true });
}

// ── Password generator────────────────────────────────────────────────
function showGenerator() {
  const o = S.gen;
  const out = h('div', { class: 'reveal-password' }, '—');
  let current = '';
  const gen = () => { current = C.generatePassword(o); out.textContent = current; meterLabel.textContent = C.strength(current).bits + ' biți'; };
  const meterLabel = h('span', { class: 'muted small' });
  const lenVal = h('span', { class: 'slider-val' }, String(o.length));
  const slider = h('input', { type: 'range', min: 8, max: 64, value: o.length, 'aria-label': 'Lungime',
    oninput: e => { o.length = +e.target.value; lenVal.textContent = e.target.value; gen(); } });
  const chip = (k, label) => {
    const b = h('button', { class: 'gen-chip' + (o[k] ? ' active' : ''), type: 'button', onclick: () => {
      o[k] = !o[k];
      if (!o.upper && !o.lower && !o.digits && !o.symbols) o[k] = true;
      b.classList.toggle('active', o[k]); gen();
    } }, label);
    return b;
  };
  const ov = modal('🎲 Generator de parole', h('div', null,
    h('div', { class: 'reveal-box' }, out, meterLabel),
    h('label', { class: 'small-label' }, 'Lungime'),
    h('div', { class: 'slider-row' }, slider, lenVal),
    h('div', { class: 'gen-options' }, chip('upper', 'ABC'), chip('lower', 'abc'), chip('digits', '123'), chip('symbols', '!@#')),
    h('div', { class: 'row' },
      h('button', { class: 'btn btn-primary', onclick: gen }, '🔄 Generează'),
      h('button', { class: 'btn btn-ghost', onclick: () => current && copy(current, 'Parolă copiată') }, '📋 Copiază')),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => ov.close() }, 'Închide')));
  gen();
}

// ── Settings───────────────────────────────────────────────────
function select(options, value, onChange) {
  const s = h('select', { class: 'select-mini', onchange: e => onChange(+e.target.value) },
    options.map(([v, l]) => h('option', { value: String(v) }, l)));
  s.value = String(value);
  return s;
}
function settingRow(label, desc, control) {
  return h('div', { class: 'setting-row' },
    h('div', { class: 'setting-row-info' }, h('div', { class: 'setting-row-label' }, label), desc && h('div', { class: 'setting-row-desc' }, desc)),
    control);
}

async function showSettings() {
  const st = S.data.settings;
  const set = k => v => { st[k] = v; persist(); resetIdle(); };
  const pol = policy();
  const setPol = k => v => updateMeta(m => { m.policy = { ...DEFAULT_POLICY, ...(m.policy || {}), [k]: v }; });
  const bioSupported = await Bio.supported();
  const hasBio = !!S.record.bio;
  const fileIn = h('input', { type: 'file', accept: '.txt,.json,text/plain,application/json', class: 'hidden', onchange: e => { S.external = false; handleImportFile(e); } });

  const ov = modal('⚙ Setări', h('div', null,
    h('div', { class: 'section-label' }, 'Backup'),
    h('button', { class: 'btn btn-primary', onclick: () => { ov.close(); doBackup(); } }, '📤 Export parole (backup criptat)'),
    h('div', { class: 'hint' }, 'Backup-ul se deschide doar cu cele 24 de cuvinte + PIN-ul. Telefonul singur nu-l poate deschide.'),

    h('div', { class: 'section-label mt16' }, 'Autodistrugere'),
    settingRow('Autodistrugere după', `PIN-uri greșite (blocare 5 min după ${LOCK_AFTER})`,
      select([[4, '4'], [5, '5'], [6, '6'], [8, '8'], [10, '10']], pol.wipeAfter, setPol('wipeAfter'))),
    settingRow('Numărătoare', hasBio ? 'Timp să anulezi cu amprenta' : 'Fără amprentă nu poate fi anulată',
      select([[10, '10 sec'], [30, '30 sec'], [60, '60 sec'], [120, '2 min']], pol.countdown, setPol('countdown'))),

    h('div', { class: 'section-label mt16' }, 'Sesiune'),
    settingRow('Blocare la inactivitate', null, select([[1, '1 min'], [2, '2 min'], [5, '5 min'], [10, '10 min'], [30, '30 min'], [0, 'Niciodată']], st.autoLockMins, set('autoLockMins'))),
    settingRow('Blocare în fundal', 'Când ieși din aplicație', select([[0, 'Imediat'], [30, '30 sec'], [60, '1 min'], [300, '5 min'], [-1, 'Niciodată']], st.hideLockSecs, set('hideLockSecs'))),
    settingRow('Golire clipboard', 'După copierea unei parole', select([[15, '15 sec'], [30, '30 sec'], [60, '1 min'], [0, 'Niciodată']], st.clipClearSecs, set('clipClearSecs'))),

    h('div', { class: 'section-label mt16' }, 'Acces'),
    settingRow('Amprentă', hasBio ? 'Activă: PIN + amprentă la deschidere' : bioSupported ? 'Neactivată' : 'Nedisponibilă aici',
      hasBio ? h('span', { class: 'badge' }, 'activă')
        : h('button', { class: 'btn btn-ghost btn-sm', disabled: !bioSupported, onclick: () => { ov.close(); enableBio(); } }, 'Activează')),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => { ov.close(); showChangePin(); } }, '🔢 Schimbă PIN-ul'),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => { ov.close(); newWords(); } }, '🗝 Cheie nouă (alte 24 de cuvinte)'),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => { S.external = 'picker'; fileIn.click(); } }, '📥 Importă parole (.txt sau backup)'),
    fileIn,

    h('div', { class: 'section-label mt16 danger' }, 'Zonă periculoasă'),
    h('button', { class: 'btn btn-danger', onclick: () => { ov.close(); confirmWipe(); } }, '💀 Șterge tot seiful'),
    h('div', { class: 'meta-line mt12' }, `Vault ${APP_VERSION} · AES-256-GCM · ${S.record.kdf.alg === 'argon2id' ? 'Argon2id 64 MiB' : 'PBKDF2 600k'} · ECDH P-256 pentru backup · totul rămâne pe telefon`),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => ov.close() }, 'Închide')));
}

// ── Backup: encrypted to the backup public key + PIN, sent via the Share sheet ──
function doBackup() {
  askAuth('📤 Export parole (backup criptat)', async ({ dek, pin }) => {
    dek.fill(0);
    try {
      const file = await C.makeBackup({ entries: S.data.entries, settings: S.data.settings, exported: Date.now() }, S.record.backup, pin, S.record.pinLen);
      const name = `vault-backup-${new Date().toISOString().slice(0, 10)}.txt`;
      if (PREVIEW) return showBackupText(JSON.stringify(file));
      const res = await shareOrDownload(name, JSON.stringify(file));
      if (res === 'shared') toast('✓ Backup trimis');
      else if (res === 'downloaded') toast('✓ Backup salvat în Descărcări');
    } catch (e) { console.error(e); toast('Eroare la backup: ' + e.message, 'err', 4000); }
  }, `Toate cele ${S.data.entries.length} parole vor fi puse într-un fișier criptat. Îl poți deschide doar pe o aplicație Vault, la „Restaurează dintr-un backup”, cu cele 24 de cuvinte + PIN-ul actual. Fără cuvinte, fișierul nu poate fi decriptat de nimeni.`);
}

// Preview only: downloads are blocked there, so show the text for copy & restore testing.
function showBackupText(text) {
  const ta = h('textarea', { class: 'mono backup-text', rows: 6, readonly: true });
  ta.value = text;
  const ov = modal('📤 Backup criptat', h('div', null,
    h('div', { class: 'info-box' }, h('strong', null, 'Previzualizare: '),
      'aici descărcarea e blocată, deci backup-ul apare ca text. Copiază-l, apoi șterge seiful și testează „Restaurează dintr-un backup” lipind textul. Pe telefon vei primi un fișier pe care îl trimiți în Drive.'),
    ta,
    h('button', { class: 'btn btn-primary mt8', onclick: () => copy(text, 'Backup copiat') }, '📋 Copiază backup-ul'),
    h('button', { class: 'btn btn-ghost mt8', onclick: () => ov.close() }, 'Închide')));
  ta.addEventListener('focus', () => ta.select());
}

async function shareOrDownload(name, text) {
  const file = new File([text], name, { type: 'text/plain' });
  if (navigator.canShare?.({ files: [file] })) {
    S.external = true;
    try { await navigator.share({ files: [file], title: 'Backup Vault' }); return 'shared'; }
    catch (e) { if (e.name === 'AbortError') return 'cancel'; }
    finally { S.external = false; }
  }
  download(name, text, 'text/plain');
  return 'downloaded';
}

function enableBio() {
  askAuth('👆 Activează amprenta', async ({ dek, pin }) => {
    try {
      const { bio, secret } = await Bio.enroll();
      const kdf = { ...C.defaultKdf(), salt: C.b64(C.rand(16)) };
      const kek = await C.deviceKey(pin, secret, kdf);
      secret.fill(0);
      const dev = await C.wrapDev(kek, dek);
      await saveRecord(r => ({ ...r, kdf, bio, wraps: { ...r.wraps, dev } }));
      toast('✓ Amprenta a fost activată');
    } catch (e) {
      console.error(e);
      toast(e.message === 'prf_unsupported' ? 'Telefonul nu suportă amprenta pentru criptare' : 'Activarea a fost anulată', 'err', 4000);
    } finally { dek.fill(0); }
  });
}

function showChangePin() {
  askAuth('🔢 Schimbă PIN-ul', ({ dek, prf }) => {
    const keepPrf = prf ? prf.slice() : null; // copy: the original is wiped after confirmation
    let len = S.record.pinLen;
    const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Salvează');
    const pin = pinField(len, { placeholder: 'PIN nou' });
    const pin2 = pinField(len, { placeholder: 'Repetă PIN-ul' });
    pin2.querySelector('.pin-display')?.remove();
    const ov = modal('🔢 PIN nou', h('form', { onsubmit: async e => {
      e.preventDefault();
      const err = checkPin(pin.input.value, pin2.input.value, len);
      if (err) { pin.error(); pin2.error(); return toast(err, 'err', 3500); }
      const done = busy(btn, 'Se salvează…');
      try {
        const kdf = { ...C.defaultKdf(), salt: C.b64(C.rand(16)) };
        const dev = await C.wrapDev(await C.deviceKey(pin.input.value, keepPrf, kdf), dek);
        await saveRecord(r => ({ ...r, pinLen: len, kdf, wraps: { ...r.wraps, dev } }));
        wipe();
        ov.close();
        toast('✓ PIN-ul a fost schimbat. Fă un backup nou: backup-urile vechi cer PIN-ul vechi.', 'ok', 4500);
      } catch (e2) { console.error(e2); done(); toast(pinErrorText(e2), 'err', 4000); } // keys kept so a retry works
    } },
      h('div', { class: 'info-box' }, 'Amprenta și cele 24 de cuvinte rămân aceleași.'),
      lengthPicker(len, n => { len = n; pin.setLen(n); pin2.setLen(n); }), field(null, pin), field(null, pin2), btn,
      h('button', { class: 'btn btn-ghost mt8', type: 'button', onclick: () => { wipe(); ov.close(); } }, 'Anulează')));
    const wipe = () => { dek.fill(0); keepPrf?.fill(0); };
    ov.onX = wipe;
  }, 'Confirmă cu PIN-ul actual.');
}

function newWords() {
  const ov = modal('🗝 Cheie nouă', h('div', null,
    h('div', { class: 'info-box warn' },
      h('strong', null, 'Folosește asta după pierderea telefonului sau a foii cu cuvinte. '),
      'Vei primi alte 24 de cuvinte. Backup-urile noi vor merge doar cu ele. Backup-urile vechi se deschid în continuare doar cu cuvintele vechi.'),
    h('div', { class: 'row' },
      h('button', { class: 'btn btn-primary', onclick: () => {
        ov.close();
        askAuth('🗝 Cheie nouă', async ({ dek }) => {
          const seed = C.rand(32);
          let rk, backup;
          try { rk = await C.wrapRecovery(dek, seed); backup = await C.makeBackupKeys(seed); }
          finally { dek.fill(0); }
          // The old words stay valid until the new ones have been written down and checked.
          showWords(seed, async () => {
            await saveRecord(r => ({ ...r, wraps: { ...r.wraps, rk }, backup }));
            route();
            toast('✓ Cheie nouă activă. Fă acum un backup nou.', 'ok', 4000);
          }, 0);
        });
      } }, 'Generează'),
      h('button', { class: 'btn btn-ghost', onclick: () => ov.close() }, 'Anulează'))));
}

async function handleImportFile(evt) {
  const file = evt.target.files[0];
  evt.target.value = '';
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) return toast('Fișier prea mare (max 10 MB)', 'err');
  const text = await file.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch {}

  if (C.validBackup(parsed)) {
    const ta = wordsArea('iwords');
    const pin = pinField(parsed.pinLen, { placeholder: 'PIN-ul din backup' });
    const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Deschide backup-ul');
    const ov = modal('📥 Importă din backup', h('form', { onsubmit: async e => {
      e.preventDefault();
      let seed;
      try { seed = await C.wordsToSeed(ta.value); } catch (er) { return toast(wordsError(er), 'err', 4000); }
      if (!(await C.checkBackupWords(parsed, seed))) return toast('Cuvintele nu sunt cheia acestui backup', 'err', 3500);
      const done = busy(btn, 'Se decriptează…');
      try {
        const data = await C.openBackup(parsed, seed, pin.input.value);
        ov.close();
        showImportPreview((data.entries || []).map(cleanEntry).filter(Boolean), false);
      } catch { done(); pin.error(); toast('PIN greșit pentru acest backup', 'err'); }
      finally { seed.fill(0); }
    } }, h('div', { class: 'info-box' }, `Backup din ${fmtDate(parsed.created)}. Intrările vor fi adăugate peste cele existente.`),
       field('Cele 24 de cuvinte ale backup-ului', ta), field('PIN-ul de atunci', pin), btn,
       h('button', { class: 'btn btn-ghost mt8', type: 'button', onclick: () => ov.close() }, 'Anulează')));
    return;
  }
  if (parsed) return toast('Format necunoscut', 'err');
  const found = parseTxtPasswords(text).map(cleanEntry).filter(Boolean);
  if (!found.length) return toast('Nu am găsit perechi utilizator/parolă în fișier', 'err', 3000);
  showImportPreview(found, true);
}

function showImportPreview(found, fromTxt) {
  const checks = found.map(() => h('input', { type: 'checkbox', checked: true }));
  const rows = found.map((it, i) => h('tr', null,
    h('td', null, checks[i]),
    h('td', { class: 'cell' }, it.site),
    h('td', { class: 'cell mono muted' }, it.username),
    h('td', { class: 'cell mono masked' }, '••••••')));
  const ov = modal('📋 Previzualizare import', h('div', null,
    h('div', { class: 'info-box' }, `Am găsit ${found.length} ${found.length === 1 ? 'intrare' : 'intrări'}. Debifează ce nu vrei să imporți.`),
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th'), h('th', null, 'Site'), h('th', null, 'Utilizator'), h('th', null, 'Parolă'))),
      h('tbody', null, rows))),
    h('div', { class: 'row mt8' },
      h('button', { class: 'btn btn-ghost btn-sm', onclick: () => checks.forEach(c => { c.checked = true; }) }, 'Toate'),
      h('button', { class: 'btn btn-ghost btn-sm', onclick: () => checks.forEach(c => { c.checked = false; }) }, 'Niciuna')),
    h('div', { class: 'row mt12' },
      h('button', { class: 'btn btn-primary', onclick: async () => {
        const key = x => `${x.site.toLowerCase()}|${x.username.toLowerCase()}|${x.password}`;
        const existing = new Set(S.data.entries.map(key));
        let added = 0;
        found.forEach((it, i) => {
          if (!checks[i].checked || existing.has(key(it))) return;
          S.data.entries.push({ ...it, id: crypto.randomUUID() });
          existing.add(key(it)); added++;
        });
        if (!(await persist())) return;
        ov.close(); refreshApp();
        toast(`✓ ${added} ${added === 1 ? 'intrare importată' : 'intrări importate'}`);
        if (fromTxt) modal('⚠️ Important', h('div', null,
          h('p', { class: 'muted mb12' }, 'Fișierul .txt conține parolele NECRIPTATE. Șterge-l acum de pe telefon (și din coșul de gunoi / cloud), altfel oricine îl găsește îți vede parolele.'),
          h('button', { class: 'btn btn-primary', onclick: () => closeAllModals() }, 'Am înțeles')));
      } }, '✓ Importă selecția'),
      h('button', { class: 'btn btn-ghost', onclick: () => ov.close() }, 'Anulează'))));
}

// .txt parser: email:pass, email|pass, email pass, labelled blocks, URL + email + password lines
function parseTxtPasswords(text) {
  const results = [], seen = new Set();
  const lines = text.split(/\r?\n/);
  const emailRe = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;
  const siteRe = /^(?:site|website|url|platform|platforma|app|aplicatie|aplicație|account|cont|service)\s*[:=]\s*(.+)/i;
  const userRe = /^(?:email|e-mail|user|username|utilizator|login|mail)\s*[:=]\s*(.+)/i;
  const passRe = /^(?:password|parola|parolă|pass|pwd|pw|key|secret)\s*[:=]\s*(.+)/i;
  let buf = { site: '', username: '', password: '' };
  const push = (site, username, password) => {
    const k = username + '|' + password;
    if (!seen.has(k)) { results.push({ site, username, password }); seen.add(k); }
  };
  const flush = () => { if (buf.username && buf.password) push(buf.site, buf.username, buf.password); buf = { site: '', username: '', password: '' }; };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) { flush(); continue; }
    let m;
    if ((m = line.match(siteRe))) { if (buf.username && buf.password) flush(); buf.site = m[1].trim(); continue; }
    if ((m = line.match(userRe))) { buf.username = m[1].trim(); continue; }
    if ((m = line.match(passRe))) { buf.password = m[1].trim(); continue; }

    const sep = line.match(/^(.+?)\s*[:|;]\s*(\S+)\s*$/) || line.match(/^([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\s+(\S+)$/);
    if (sep) {
      const em = sep[1].match(emailRe);
      if (em && sep[2].length >= 3) {
        const u = sep[1].match(/https?:\/\/([^\/\s]+)/);
        push(buf.site || (u ? u[1] : ''), em[0], sep[2]);
        buf = { site: '', username: '', password: '' };
        continue;
      }
    }
    if ((m = line.match(/^https?:\/\/([^\/\s]+)/))) { buf.site = m[1]; continue; }
    const em = line.match(emailRe);
    if (em && line === em[0]) {
      const next = (lines[i + 1] || '').trim();
      if (next && !emailRe.test(next) && !/[:|]/.test(next) && next.length >= 3) {
        push(buf.site, em[0], next);
        buf = { site: '', username: '', password: '' };
        i++;
      } else buf.username = em[0];
    }
  }
  flush();
  return results.map(r => ({ ...r, site: r.site || r.username.split('@')[1] || 'Import' }));
}

// ── Service worker (offline + home-screen install) ──
function registerSW() {
  if (!('serviceWorker' in navigator)) return;
  let url = './sw.js';
  if (window.trustedTypes) {
    const policy = trustedTypes.createPolicy('vault-sw', { createScriptURL: u => { if (u !== './sw.js') throw new Error('blocked'); return u; } });
    url = policy.createScriptURL(url);
  }
  navigator.serviceWorker.register(url).catch(err => console.warn('SW:', err));
}

// ── Boot ───────────────────────────────────────────────────────
// Only one copy of the app may run at a time (otherwise each tab would get its own attempts).
function claimSingleInstance() {
  if (!navigator.locks) return Promise.resolve(true);
  return new Promise(resolve => {
    navigator.locks.request('vault-instance', { ifAvailable: true }, lock => {
      resolve(!!lock);
      return lock ? new Promise(() => {}) : null; // hold the lock for the life of the page
    }).catch(() => resolve(true));
  });
}

async function boot() {
  if (!window.isSecureContext || !crypto?.subtle || !window.indexedDB) {
    mount(h('div', { class: 'card' }, lockVisual('⚠️', 'Mediu nesigur',
      'Aplicația trebuie deschisă prin HTTPS (ex. GitHub Pages) într-un browser modern. Criptarea nu e disponibilă aici.')));
    return;
  }
  if (!(await claimSingleInstance())) {
    mount(h('div', { class: 'card' }, lockVisual('🔐', 'Vault e deja deschis', 'Aplicația rulează deja în altă filă sau fereastră. Închide-o pe aceea, apoi reîncarcă pagina.'),
      h('button', { class: 'btn btn-primary', onclick: () => location.reload() }, 'Reîncarcă')));
    return;
  }
  try {
    S.record = await DB.get('vault') || null;
    S.meta = { ...DEFAULT_META, ...(await DB.get('meta') || {}) };
  } catch (e) {
    mount(h('div', { class: 'card' }, lockVisual('⚠️', 'Stocare indisponibilă', 'Browserul blochează stocarea locală (mod privat?).')));
    return;
  }
  navigator.storage?.persist?.().catch(() => {});
  registerSW();
  await enforceAttemptPolicy();
  route();
}
boot();
