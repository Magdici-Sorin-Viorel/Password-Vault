// ════════════════════════════════════════════════════════════════
// VAULT — crypto.js (v5)
// All cryptography runs locally: Web Crypto (native) + Argon2id (hash-wasm, bundled).
//
// ON THE PHONE
//   • A random 256-bit data key (DEK) encrypts the vault with AES-256-GCM.
//   • The DEK is wrapped with a key derived from Argon2id(PIN) + the fingerprint secret
//     (WebAuthn PRF). Both are required to unwrap it.
//   • The DEK is also wrapped with a key derived from the 24 words (forgotten-PIN recovery).
//
// BACKUP (crypto-wallet style)
//   • The 24 words (256 bits) protect an ECDH P-256 key pair.
//   • The phone keeps ONLY the public key (plus the private key encrypted with the words,
//     which it cannot open).
//   • Each backup is encrypted to the public key (ephemeral ECDH) + the PIN.
//   • Opening a backup requires the 24 words + the PIN. The phone alone cannot.
// ════════════════════════════════════════════════════════════════
import { WORDS } from './words.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = crypto.subtle;

export const rand = n => crypto.getRandomValues(new Uint8Array(n));
export function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
export function unb64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};

// ── PIN derivation: Argon2id (slow and memory-hard against GPU cracking) ──
const ARGON = { alg: 'argon2id', m: 65536, t: 3, p: 1 };   // 64 MiB, 3 passes
const PBKDF = { alg: 'pbkdf2', iter: 600_000 };            // fallback if WebAssembly is blocked
export const argonAvailable = () => typeof globalThis.hashwasm?.argon2id === 'function';
export const defaultKdf = () => argonAvailable() ? { ...ARGON } : { ...PBKDF };

export async function pinBits(pin, salt, kdf) {
  if (kdf.alg === 'argon2id') {
    if (!argonAvailable()) throw new Error('argon_unavailable');
    return globalThis.hashwasm.argon2id({
      password: pin, salt, parallelism: kdf.p, iterations: kdf.t, memorySize: kdf.m, hashLength: 32, outputType: 'binary',
    });
  }
  const base = await subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', salt, iterations: kdf.iter, hash: 'SHA-256' }, base, 256));
}

// ── HKDF → AES key ───────────────────────────────────────────
export async function hkdfKey(ikm, salt, info) {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function hkdfBytes(ikm, salt, info, n = 32) {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, base, n * 8));
}

// ── AES-256-GCM with AAD ─────────────────────────────────────────
export async function seal(key, bytes, aad) {
  const iv = rand(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes));
  return { iv: b64(iv), ct: b64(ct) };
}
export async function open(key, box, aad) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv), additionalData: enc.encode(aad) }, key, unb64(box.ct)));
}
export const importDek = raw => subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
export const encryptPayload = (key, obj) => seal(key, enc.encode(JSON.stringify(obj)), 'vault:data:v5');
export const decryptPayload = async (key, box) => JSON.parse(dec.decode(await open(key, box, 'vault:data:v5')));

// ── Device key: PIN (+ fingerprint) ────────────────────────────
export async function deviceKey(pin, prf, kdf) {
  const salt = unb64(kdf.salt);
  const bits = await pinBits(pin, salt, kdf);
  const ikm = prf ? concat(bits, prf) : bits;
  const key = await hkdfKey(ikm, salt, prf ? 'vault:device:pin+bio:v5' : 'vault:device:pin:v5');
  bits.fill(0); ikm.fill(0);
  return key;
}
export const wrapDev = (kek, dek) => seal(kek, dek, 'vault:wrap:dev');
export const unwrapDev = (kek, w) => open(kek, w, 'vault:wrap:dev');

// Checks that the fingerprint secret is the enrolled one (reveals nothing about the PIN)
export const bioCheck = async prf => b64(await hkdfBytes(prf, new Uint8Array(0), 'vault:bio-check', 16));

// ── The 24 words (BIP39: 256 bits + checksum) ─────────────────
export async function seedToWords(seed) {
  const hash = new Uint8Array(await subtle.digest('SHA-256', seed));
  let bits = '';
  for (const b of seed) bits += b.toString(2).padStart(8, '0');
  bits += hash[0].toString(2).padStart(8, '0');
  const out = [];
  for (let i = 0; i < 24; i++) out.push(WORDS[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
  return out;
}
export async function wordsToSeed(text) {
  const words = text.toLowerCase().normalize('NFKD').replace(/[^a-z\s]/g, ' ').trim().split(/\s+/).filter(Boolean);
  if (words.length !== 24) { const e = new Error('bad_length'); e.count = words.length; throw e; }
  let bits = '';
  for (const w of words) {
    let i = WORDS.indexOf(w);
    if (i < 0) { // accept the first 4 letters, like crypto wallets do
      const m = w.length >= 4 ? WORDS.filter(x => x.startsWith(w.slice(0, 4))) : [];
      if (m.length !== 1) { const e = new Error('bad_word'); e.word = w; throw e; }
      i = WORDS.indexOf(m[0]);
    }
    bits += i.toString(2).padStart(11, '0');
  }
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const hash = new Uint8Array(await subtle.digest('SHA-256', seed));
  if (parseInt(bits.slice(256), 2) !== hash[0]) throw new Error('bad_checksum');
  return seed;
}
export const seedCheck = async seed => b64(await hkdfBytes(seed, new Uint8Array(0), 'vault:seed-check', 8));

// On-phone recovery (forgotten PIN): DEK wrapped with a key derived from the words
export async function wrapRecovery(dek, seed) {
  const salt = rand(16);
  return { salt: b64(salt), ...(await seal(await hkdfKey(seed, salt, 'vault:recovery'), dek, 'vault:wrap:rk')) };
}
export async function unwrapRecovery(w, seed) {
  return open(await hkdfKey(seed, unb64(w.salt), 'vault:recovery'), w, 'vault:wrap:rk');
}

// ── Backup keys (ECDH P-256) ────────────────────────────
// The private key is encrypted with the words and embedded in every backup; the phone keeps only the public key.
export async function makeBackupKeys(seed) {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const priv = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
  const salt = rand(16);
  const box = await seal(await hkdfKey(seed, salt, 'vault:backup-priv'), priv, 'vault:backup-priv');
  priv.fill(0);
  return { pub: b64(pub), encPriv: { salt: b64(salt), ...box }, seedCheck: await seedCheck(seed) };
}

// The backup header is bound into the AAD, so it cannot be altered undetected.
const backupAad = f => `vault:backup:v5|${f.pinLen}|${f.created}|${JSON.stringify(f.kdf)}|${f.ephPub}`;

// Accept only backups with sane, known parameters (a crafted file must not freeze the app).
export function validBackup(f) {
  if (!f || f.format !== 'vault-backup' || f.v !== 5) return false;
  if (![4, 6, 8].includes(f.pinLen)) return false;
  const k = f.kdf || {};
  const okKdf = (k.alg === 'argon2id' && k.m === ARGON.m && k.t === ARGON.t && k.p === ARGON.p)
    || (k.alg === 'pbkdf2' && k.iter === PBKDF.iter);
  return okKdf && typeof k.salt === 'string' && [f.ephPub, f.iv, f.ct, f.seedCheck].every(x => typeof x === 'string')
    && f.encPriv && typeof f.encPriv.salt === 'string';
}

export async function makeBackup(obj, keys, pin, pinLen) {
  const recipient = await subtle.importKey('raw', unb64(keys.pub), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256));
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const kdf = { ...defaultKdf(), salt: b64(rand(16)) };
  const pb = await pinBits(pin, unb64(kdf.salt), kdf);
  const key = await hkdfKey(concat(shared, pb), ephPub, 'vault:backup:v5');
  shared.fill(0); pb.fill(0);
  const head = { format: 'vault-backup', v: 5, created: Date.now(), pinLen, kdf, ephPub: b64(ephPub) };
  const box = await seal(key, enc.encode(JSON.stringify(obj)), backupAad(head));
  return { ...head, encPriv: keys.encPriv, seedCheck: keys.seedCheck, ...box };
}

// Separate steps so the UI can tell exactly what is wrong: the words or the PIN.
export async function checkBackupWords(file, seed) {
  return (await seedCheck(seed)) === file.seedCheck;
}
export async function openBackup(file, seed, pin) {
  const privRaw = await open(await hkdfKey(seed, unb64(file.encPriv.salt), 'vault:backup-priv'), file.encPriv, 'vault:backup-priv');
  const priv = await subtle.importKey('pkcs8', privRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  privRaw.fill(0);
  const ephPub = unb64(file.ephPub);
  const eph = await subtle.importKey('raw', ephPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: eph }, priv, 256));
  const pb = await pinBits(pin, unb64(file.kdf.salt), file.kdf);
  const key = await hkdfKey(concat(shared, pb), ephPub, 'vault:backup:v5');
  shared.fill(0); pb.fill(0);
  return JSON.parse(dec.decode(await open(key, file, backupAad(file))));
}

// ── Password generator (no modulo bias) ──────────────────────
export function randInt(n) {
  const lim = Math.floor(0x100000000 / n) * n;
  const a = new Uint32Array(1);
  for (;;) { crypto.getRandomValues(a); if (a[0] < lim) return a[0] % n; }
}
export function generatePassword({ length = 20, upper = true, lower = true, digits = true, symbols = true } = {}) {
  const pools = [];
  if (lower) pools.push('abcdefghijkmnpqrstuvwxyz');
  if (upper) pools.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (digits) pools.push('23456789');
  if (symbols) pools.push('!@#$%^&*_-+=?');
  if (!pools.length) pools.push('abcdefghijkmnpqrstuvwxyz');
  const all = pools.join('');
  const out = pools.map(p => p[randInt(p.length)]);
  while (out.length < length) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.slice(0, length).join('');
}

const COMMON = ['password', 'parola', 'qwerty', '123456', '111111', 'admin', 'iloveyou', 'letmein', 'welcome', 'abc123', 'azerty', 'romania'];
export function strength(pw) {
  if (!pw) return { bits: 0, score: 0, label: '' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(Math.max(pool, 2));
  if (new Set(pw).size < pw.length / 2) bits *= 0.6;
  if (COMMON.some(w => pw.toLowerCase().includes(w))) bits *= 0.5;
  if (/^(.)\1*$/.test(pw)) bits = 2;
  const score = bits < 40 ? 0 : bits < 60 ? 1 : bits < 80 ? 2 : bits < 100 ? 3 : 4;
  return { bits: Math.round(bits), score, label: ['FOARTE SLABĂ', 'SLABĂ', 'OK', 'PUTERNICĂ', 'EXCELENTĂ'][score] };
}
