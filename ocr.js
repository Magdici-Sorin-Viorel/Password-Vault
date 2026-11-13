// ════════════════════════════════════════════════════════════════
// VAULT — ocr.js
// Reads text from photos entirely on the device, using Tesseract (WebAssembly),
// bundled in vendor/tesseract/. The image never leaves the phone.
// ════════════════════════════════════════════════════════════════

const BASE = new URL('./vendor/tesseract/', document.baseURI).href;
const WORKER_URL = BASE + 'worker.min.js';
const DIR = BASE.replace(/\/$/, '');

let worker = null;
let progressCb = null;

// The page enforces Trusted Types. Tesseract creates its Web Worker from a plain URL,
// so a default policy allows exactly that one same-origin script and nothing else.
function allowWorkerUrl() {
  const tt = window.trustedTypes;
  if (!tt || tt.defaultPolicy) return;
  try {
    tt.createPolicy('default', {
      createScriptURL: u => (new URL(u, document.baseURI).href === WORKER_URL ? WORKER_URL : null),
    });
  } catch (e) { console.warn('OCR policy:', e); }
}

function withTimeout(promise, ms, code) {
  let t;
  return Promise.race([
    promise,
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(code)), ms); }),
  ]).finally(() => clearTimeout(t));
}

async function getWorker() {
  if (worker) return worker;
  if (!globalThis.Tesseract) throw new Error('ocr_unavailable');
  allowWorkerUrl();
  const init = globalThis.Tesseract.createWorker('eng', 1, {
    workerPath: WORKER_URL,
    corePath: DIR,
    langPath: DIR,
    workerBlobURL: false,
    gzip: true,
    cacheMethod: 'none',          // the service worker caches the files; nothing extra is stored
    logger: m => progressCb?.(m),
    errorHandler: e => console.error('OCR worker:', e),
  });
  // The first run downloads ~10 MB (engine + language data).
  const w = await withTimeout(init, 120_000, 'ocr_load_failed');
  await w.setParameters({ preserve_interword_spaces: '1' });
  worker = w;
  return w;
}

export async function terminate() {
  const w = worker;
  worker = null; progressCb = null;
  try { await w?.terminate(); } catch { /* already gone */ }
}

// ── Image preparation ──────────────────────────────────────────
function canvasFrom(bitmap, scale) {
  const c = document.createElement('canvas');
  c.width = Math.max(1, Math.round(bitmap.width * scale));
  c.height = Math.max(1, Math.round(bitmap.height * scale));
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(bitmap, 0, 0, c.width, c.height);
  return c;
}

// Greyscale, stretch contrast, and invert dark-mode screenshots (the engine reads
// dark text on a light background best).
function enhance(canvas) {
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const d = img.data;
  const hist = new Uint32Array(256);
  let sum = 0;
  for (let i = 0; i < d.length; i += 4) {
    const y = (d[i] * 77 + d[i + 1] * 150 + d[i + 2] * 29) >> 8;
    d[i] = y; hist[y]++; sum += y;
  }
  const n = d.length / 4;
  const invert = sum / n < 110;
  let lo = 0, hi = 255, acc = 0;
  for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc >= n * 0.02) { lo = v; break; } }
  acc = 0;
  for (let v = 255; v >= 0; v--) { acc += hist[v]; if (acc >= n * 0.02) { hi = v; break; } }
  const range = Math.max(1, hi - lo);
  const lut = new Uint8ClampedArray(256);
  for (let v = 0; v < 256; v++) {
    const s = Math.max(0, Math.min(255, Math.round((v - lo) * 255 / range)));
    lut[v] = invert ? 255 - s : s;
  }
  for (let i = 0; i < d.length; i += 4) { const y = lut[d[i]]; d[i] = d[i + 1] = d[i + 2] = y; d[i + 3] = 255; }
  ctx.putImageData(img, 0, 0);
  return canvas;
}

async function prepare(file) {
  let bitmap;
  try { bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' }); }
  catch { throw new Error('bad_image'); }
  const long = Math.max(bitmap.width, bitmap.height);
  // Preview shown to the user next to the recognised text (kept in colour).
  const view = canvasFrom(bitmap, Math.min(1, 1600 / long));
  // OCR input: cap huge camera photos, enlarge small screenshots so letters are big enough.
  let scale = Math.min(1, 2400 / long);
  if (bitmap.width * scale < 1200) scale = Math.min(2.5, 1200 / bitmap.width, 2400 / long);
  const input = enhance(canvasFrom(bitmap, scale));
  bitmap.close?.();
  return { view, input };
}

// Recognise one image. `onProgress({ status, progress })` reports loading and reading.
// Resolves { text, confidence (0–100), view (canvas) }.
export async function recognize(file, onProgress) {
  const { view, input } = await prepare(file);
  progressCb = onProgress || null;
  try {
    const w = await getWorker();
    const { data } = await withTimeout(w.recognize(input, {}, { text: true }), 180_000, 'ocr_timeout');
    return { text: data.text || '', confidence: Math.round(data.confidence || 0), view };
  } catch (e) {
    await terminate(); // a failed or stuck worker is not reused
    throw e;
  } finally {
    progressCb = null;
    input.width = input.height = 0; // release the pixel buffer
  }
}
