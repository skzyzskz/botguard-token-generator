/**
 */
import { Window } from 'happy-dom';
import { createRequire } from 'module';
import crypto from 'crypto';

// Redirect all console.log/warn/error to stderr so stdout is clean for token output
const _origLog = console.log, _origWarn = console.warn, _origErr = console.error;
console.log = (...a) => process.stderr.write(a.join(' ') + '\n');
console.warn = (...a) => process.stderr.write(a.join(' ') + '\n');
console.error = (...a) => process.stderr.write(a.join(' ') + '\n');
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_GLIF_HAR = path.join(SCRIPT_DIR, 'accounts.google.com.har');
const require = createRequire(import.meta.url);
const { CurlRequest } = require('curl-cffi');
const { CurlOpt, CurlHttpVersion } = require('@tocha688/libcurl');
const BotGuardClient = require('bgutils-js').BG.BotGuardClient;

const SERVICE = 'mail';
const cu = 'https://mail.google.com/mail/u/0/';
const BABLOSOFT_KEY = process.env.BABLOSOFT_KEY || 'd473ZEN5wDuMa1SnMN7fInHgh2p4V1X5yPuUv9Dg7G8BhRyJi3JRYE3WDAXg8mhS';
let _babloPayload = null;
let _babloChromeMajor = null;
let _babloFP = null;
async function fetchBabloFingerprint() {
  if (_babloFP) return _babloFP;
  try {
    const r = await fetch(`https://fingerprints.bablosoft.com/prepare?tags=Microsoft+Windows,Chrome&key=${BABLOSOFT_KEY}`);
    const d = await r.json();
    if (d.valid && d.payload) {
      _babloPayload = d.payload;
      _babloFP = d;
      const cm = d.ua?.match(/Chrome\/(\d+)/);
      if (cm) _babloChromeMajor = Number(cm[1]);
      try { _babloFP._uad = JSON.parse(Buffer.from(d.useragentdata, 'base64').toString()); } catch {}
      console.log(`[bablo] fingerprint ${d.payload.length}ch chrome=${_babloChromeMajor} gpu=${d.webgl_properties?.unmaskedRenderer?.substring(0,50)} fonts=${d.fonts?.length}`);
    }
  } catch (e) { console.log('[bablo] fetch failed:', e.message); }
  return _babloFP;
}
const EMAIL = process.argv[2] || 'cagrudisc@gmail.com';
const PASSWORD = process.argv[3] || 'Cagri123321';
const _dbeRaw = process.env.GLIF_HTTP_DEBUG;
const GLIF_HTTP_DEBUG =
  process.argv.includes('--http-debug')
  ? true
  : process.argv.includes('--no-http-debug')
  ? false
  : (_dbeRaw == null || String(_dbeRaw) === '')
  ? true
  : !/^(0|false|no|off)$/i.test(String(_dbeRaw));
const GLIF_HTTP_DEBUG_VERBOSE =
  process.argv.includes('--http-debug-verbose') ||
  /^(2|verbose|all)$/i.test(String(process.env.GLIF_HTTP_DEBUG ?? ''));
if (GLIF_HTTP_DEBUG)
  console.log(
    `[GLIF] HTTP izleme varsayılan AÇIK (verbose=${GLIF_HTTP_DEBUG_VERBOSE}). Sessiz: GLIF_HTTP_DEBUG=0 veya --no-http-debug`,
  );
const proxyArgIdx = process.argv.indexOf('--proxy');
const PROXY = proxyArgIdx >= 0 ? (process.argv[proxyArgIdx + 1]?.startsWith('http') ? process.argv[proxyArgIdx + 1] : `http://6a324296411f9031be71__cr.tr__sid.fin${Date.now()}:f25309ca304f8dfd@gw.dataimpulse.com:823`) : undefined;
const GLIF_JA4R_LEGACY = String(process.env.GLIF_JA4R || '').trim();
/** curl-cffi `impersonate` sırası; SSL 35 ve Google `400 malformed` yanıtlarında tur atılır (`GLIF_CF_SSL_RETRIES`). */
function parseCfImpersonateList() {
  const def = ['chrome136', 'chrome131', 'chrome133a', 'chrome142', 'edge101'];
  const raw = String(process.env.GLIF_CF_IMPERSONATE || '').trim();
  if (!raw) return def;
  return raw.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
}
const CF_IMPERSONATES = parseCfImpersonateList();
const CF_SSL_ROUND_CAP = Math.max(
  CF_IMPERSONATES.length,
  Math.min(96, Math.max(8, Number(process.env.GLIF_CF_SSL_RETRIES || 24) || 24)),
);
let _cffiPinned = '';
/** curl-cffi slugs: `chrome136` → 136, `chrome133a` → 133 */
function glifImpersonateChromeMajor(slug) {
  const s = String(slug || '').toLowerCase();
  if (s.startsWith('chrome133a')) return 133;
  const m = s.match(/^chrome(\d{2,3})\b/);
  return m ? Number(m[1]) : null;
}
/**
 * batchexecute / sec-ch / BG: TLS (impersonate) ile aynı Chrome ana sürümü.
 * Önce `GLIF_UA_CHROME_MAJOR`; yoksa `_cffiPinned` / `GLIF_CF_IMPERSONATE` içindeki ilk `chrome*`.
 */
function glifResolvedChromeMajor() {
  const envM = Number(process.env.GLIF_UA_CHROME_MAJOR || '');
  if (Number.isFinite(envM) && envM >= 67 && envM <= 999) return Math.floor(envM);
  const order = [_cffiPinned, ...CF_IMPERSONATES].filter(Boolean);
  for (const imp of order) {
    const mj = glifImpersonateChromeMajor(imp);
    if (mj != null) return mj;
  }
  if (_babloChromeMajor) return _babloChromeMajor;
  return 136;
}
function glifActiveUAChrome() {
  const mj = glifResolvedChromeMajor();
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${mj}.0.0.0 Safari/537.36`;
}
/** XHR / pasif isteklerde `sec-ch-ua*` tek kaynak (rrk≈46: UA 148 + TLS 136 çelişkisini önler). */
function glifChromeSecChHeaders() {
  const mj = glifResolvedChromeMajor();
  const v = String(mj);
  const fv = `${mj}.0.0.0`;
  return {
    'sec-ch-ua': `"Google Chrome";v="${v}", "Chromium";v="${v}", "Not_A Brand";v="8"`,
    'sec-ch-ua-arch': '"x86"',
    'sec-ch-ua-bitness': '"64"',
    'sec-ch-ua-full-version-list': `"Google Chrome";v="${fv}", "Chromium";v="${fv}", "Not_A Brand";v="8.0.0.0"`,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-model': '""',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua-platform-version': '"19.0.0"',
    'sec-ch-ua-wow64': '?0',
  };
}
/** `accounts.google.com` doküman GET: varsayılan Node `fetch` (libcurl bu zincirde sık 400). Tam curl: `GLIF_ACCOUNTS_NAV_FETCH=0`. Proxy varsa curl-cffi. */
const GLIF_ACCOUNTS_NAV_FETCH = process.env.GLIF_ACCOUNTS_NAV_FETCH !== '0';
/** `play.google.com/log` POST: curl-cffi sık “illegal request” 400 — proxy yokken Node `fetch`. Kapat: `GLIF_PLAY_LOG_FETCH=0` */
const GLIF_PLAY_LOG_FETCH = process.env.GLIF_PLAY_LOG_FETCH !== '0';
/**
 * `batchexecute` / `browserinfo` için Node `fetch`: yalnız `GLIF_ACCOUNTS_RPC_FETCH=1`.
 * Varsayılan **curl-cffi** — `sec-ch-ua` / UA majörü impersonate ile hizalı (başlıca **rrk≈46** önlemi).
 */
const GLIF_ACCOUNTS_RPC_FETCH = process.env.GLIF_ACCOUNTS_RPC_FETCH === '1';
/** Tek `www.google.com` GET → **NID** (proxy yok). Kapat: `GLIF_PRIME_WWW_GOOGLE=0` */
const GLIF_PRIME_WWW_GOOGLE = process.env.GLIF_PRIME_WWW_GOOGLE !== '0';
/**
 * cycleTLS seçenekleri: isteğe bağlı ek `userAgent` (`GLIF_CF_INJECT_UA=1`).
 * Gövde/header’daki UA ve sec-ch için `glifActiveUAChrome()` kullanılır.
 */
function tlsBase(extra) {
  const base = { proxy: PROXY || '', ...extra };
  if (process.env.GLIF_CF_INJECT_UA === '1') return { userAgent: glifActiveUAChrome(), ...base };
  return base;
}

/** Windows API key from public reverse of chrome.dll (dsekz/chrome-x-browser-validation-header). */
const XBV_WIN_API_KEY = 'AIzaSyA2KlwBX3mkFo30om9LUFYQhpqLoa_BNhE';
/**
 * x-browser-validation = Base64(SHA-1( optionalSeed + API_KEY + User-Agent ))
 * Seed: branded Chrome 147+ may prepend bytes (see Kameleo / chromium integrity_seed). If you captured it from your chrome.dll, set CHROME_XBV_SEED (utf8) or CHROME_XBV_SEED_B64.
 */
function xBrowserValidationForUA(userAgent) {
  const fromEnv = process.env.X_BROWSER_VALIDATION;
  if (fromEnv) return fromEnv;
  const seedB64 = process.env.CHROME_XBV_SEED_B64;
  const seed = seedB64
    ? Buffer.from(seedB64, 'base64')
    : Buffer.from(process.env.CHROME_XBV_SEED || '', 'utf8');
  return crypto
    .createHash('sha1')
    .update(Buffer.concat([seed, Buffer.from(XBV_WIN_API_KEY + userAgent, 'utf8')]))
    .digest('base64');
}
/** Glif identifier field: HAR (turalsozen) used local part only for @gmail.com */
function signinIdentifierLocalPart(email) {
  const s = String(email).trim();
  if (s.toLowerCase().endsWith('@gmail.com')) return s.slice(0, -10);
  return s;
}

/** curl-cffi örnekleri (libcurl impersonate); `keepAlive`/multi-reuse kapalı BG risklerine yakın davranmak için düşük seviye yönetilir. */
const _cffiCtor = {
  timeout: Math.min(300000, Math.max(8000, Number(process.env.GLIF_CF_TIMEOUT_MS || 90000) || 90000)),
};
if (PROXY) _cffiCtor.proxy = PROXY;
if (process.env.GLIF_CF_INSECURE === '1') _cffiCtor.verify = false;
const _curlCli = new CurlRequest(_cffiCtor);
if (GLIF_HTTP_DEBUG && GLIF_JA4R_LEGACY)
  console.warn(
    '[GLIF] GLIF_JA4R (eski CycleTLS) tanımlı — curl-cffi desteklemiyor; TLS için `GLIF_CF_IMPERSONATE` kullanın.',
  );
const jar = {};
/** accounts.google.com.har başarılı seri: ilk batchexecute `_reqid=70635`, sonra her adımda +100000 */
let reqC = 70635;

/**
 * kimlik HTML’inde `meta name="referrer" content="origin"` → gerçek tarayıcı XHR’larında Referer
 * tam identifier URL’si DEĞİL, köken: https://accounts.google.com/ (HAR’da böyle).
 * Sayfa URL’si buraya yazılmaz; aksi takdirde BotGuard ile batchexecute uyumsuzluğu (rrk≈46) riski.
 */
let accountsGlifDocReferer = 'https://accounts.google.com/';

function qpGetDecode(url, param) {
  try {
    const m = String(url).match(new RegExp(`[?&]${param}=([^&]*)`));
    if (!m) return '';
    return decodeURIComponent(String(m[1]).replace(/\+/g, ' '));
  } catch {
    return '';
  }
}

function tlsResponseBodyToUtf8(resp) {
  const d = resp?.data;
  if (d == null) return '';
  if (typeof d === 'string') return d;
  if (Buffer.isBuffer(d)) return d.toString('utf8');
  if (d instanceof Uint8Array) return Buffer.from(d).toString('utf8');
  try {
    if (typeof d === 'object' && typeof d.toString === 'function')
      return d.toString('utf8');
  } catch (_) {}
  return String(d);
}
function ck(){return Object.entries(jar).map(([k,v])=>`${k}=${v}`).join('; ')}
/** Set-Cookie: virgülle bölmeyin — Expires=Wed, 21 Oct … içindeki virgül tüm mantığı bozar. */
function pc(h){
  for (const hk of ['Set-Cookie','set-cookie']) {
    const raw = h?.[hk];
    if (raw == null) continue;
    const lines = Array.isArray(raw) ? raw : [String(raw)];
    for (let line of lines) {
      line = line.trim();
      if (!line) continue;
      const semi = line.indexOf(';');
      const pair = semi >= 0 ? line.slice(0, semi).trim() : line;
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      if (name.includes(' ')) continue;
      jar[name] = pair.slice(eq + 1).trim();
    }
  }
}

let __glifHttpSeq = 0;
let __glifFetchSeq = 0;

function glifDbgShort(str, max = 140) {
  const s = str == null ? '' : String(str);
  return s.length > max ? `${s.slice(0, Math.max(0, max - 1))}…` : s;
}

function glifSanitizeLogText(s, maxLen) {
  let t =
    typeof s === 'string' ? s
    : Buffer.isBuffer(s) ? s.toString('utf8')
    : String(s ?? '');
  const localPart = typeof signinIdentifierLocalPart === 'function' ? signinIdentifierLocalPart(EMAIL) : '';
  if (EMAIL && EMAIL.length > 4) t = t.split(EMAIL).join('***email***');
  if (localPart && localPart.length > 2) t = t.split(localPart).join('***local***');
  if (PASSWORD && PASSWORD.length > 0) t = t.split(PASSWORD).join('***pw***');
  const cap =
    typeof maxLen === 'number'
      ? maxLen
      : GLIF_HTTP_DEBUG_VERBOSE
      ? 20000
      : 3800;
  if (t.length > cap) return `${t.slice(0, cap)} … [${t.length - cap} byte daha`;
  return t;
}

/** İstek Cookie satırında sadece isimleri yaz (ham değerleri loglama). */
function glifCookieNamesSummary(cookieHeader) {
  if (cookieHeader == null || cookieHeader === '') return '(cookie yok)';
  const parts = String(cookieHeader).split(';');
  const names = parts.map(p => p.split('=')[0].trim()).filter(Boolean);
  const u = [...new Set(names)];
  const head = u.slice(0, 18).join(', ');
  return u.length > 18 ? `${head} …+${u.length - 18}` : head || '(pars edilemedi)';
}

function glifLogOutgoingHeaders(hdrs) {
  if (!hdrs || typeof hdrs !== 'object') return;
  const want = [
    'accept',
    'accept-language',
    'cache-control',
    'content-type',
    'origin',
    'referer',
    'pragma',
    'priority',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'sec-ch-ua-full-version-list',
    'x-browser-validation',
    'x-goog-ext-278367001-jspb',
    'x-goog-ext-391502476-jspb',
    'x-same-domain',
    'cookie',
    'upgrade-insecure-requests',
    'user-agent',
  ];
  for (const w of want) {
    const k = Object.keys(hdrs).find(x => String(x).toLowerCase() === w);
    if (!k || hdrs[k] == null || hdrs[k] === '') continue;
    let val = hdrs[k];
    if (w === 'cookie') val = `[${glifCookieNamesSummary(val)}]`;
    else if (w === 'x-browser-validation') val = glifDbgShort(String(val), 44);
    else val = glifDbgShort(String(val), 260);
    console.log(`       h ${k}: ${val}`);
  }
}

function glifLogSetCookieSummary(hdrs) {
  const raw = hdrs?.['Set-Cookie'] ?? hdrs?.['set-cookie'];
  if (raw == null) return;
  const lines = Array.isArray(raw) ? raw : [String(raw)];
  console.log(`       Set-Cookie: ${lines.length} satır`);
  for (let i = 0; i < Math.min(lines.length, 8); i++) {
    const line = String(lines[i]);
    console.log(`          [${i}] ${glifDbgShort(line.replace(/\s+/g, ' ').trim(), 130)}`);
  }
}

function glifPeekResponseChars(r, maxPeek) {
  const d = r?.data;
  if (d == null) return { len: 0, text: '', note: '(data yok)' };
  let len = 0;
  try {
    if (Buffer.isBuffer(d)) len = d.length;
    else if (d instanceof Uint8Array) len = d.byteLength;
    else if (typeof d === 'string') len = d.length;
    else if (typeof d?.byteLength === 'number') len = d.byteLength;
  } catch (_) {}
  let text = tlsResponseBodyToUtf8(r);
  const notes = [];
  let samp;
  try {
    if (Buffer.isBuffer(d)) samp = d.subarray(0, 4);
    else if (typeof d === 'string') samp = Buffer.from(d.slice(0, 4), 'latin1');
  } catch (_) {}
  if (samp && samp.length >= 2 && samp[0] === 0x1f && samp[1] === 0x8b)
    notes.push('gzip imzası');
  const effLen = len || text.length;
  if (!GLIF_HTTP_DEBUG_VERBOSE && text.length > maxPeek) {
    notes.push(`tam gövde ~${effLen}b (verbose ile daha uzun)`);
    text = text.slice(0, maxPeek);
  }
  return { len: effLen, text, note: notes.join('; ') };
}

/** Başarılı oturuma sabitlenen profil ilk sırada; SSL hatasında sıfırlanır — `GLIF_CF_IMPERSONATE` turuyla devam. */
function glifCfRotateImpersonateOrder() {
  const list = CF_IMPERSONATES.slice();
  if (_cffiPinned && list.includes(_cffiPinned))
    return [_cffiPinned, ...list.filter(x => x !== _cffiPinned)];
  return list;
}
/** libcurl/ssl el sıkışması ve sık bağlantı kırılması yeniden denemesi için. */
function glifCfSslRecoverable(e) {
  const m = String(e && e.message != null ? e.message : e || '');
  const code = e && e.code;
  if (typeof code === 'number' && (code === 35 || code === 52 || code === 56)) return true;
  if (typeof code === 'string' && /ssl|tls|certificate/i.test(code) && String(e?.message || '').length < 320)
    return true;
  return /\b(ssl|tls|OPENSSL|CERT|certificate|Handshake|handshake|\bDECODE\b|UNSUPPORTED_PROTOCOL|ECONNRESET|Connection was reset|connection.*reset\b)/i.test(
    m,
  );
}
/** Google “Error 400 … malformed” (özellikle libcurl yüzök + `continue=…` parametreleri) — curl-cffi’de impersonate turuyla deneme. */
function glifCfGoogleMalformed400(legacyResp, reqUrlStr) {
  try {
    if (Number(legacyResp?.status) !== 400) return false;
    const hn = new URL(String(reqUrlStr)).hostname || '';
    if (!/(\.|^)google\.com$/i.test(hn)) return false;
    /** `play.google.com/log` için curl yanlış sürüm / istemci yüzükü sık bozuyor — burada yanlış “malformed turu” dönmez (fetch veya atlama kullanılır). */
    if (/^play\.google\.com$/i.test(hn)) return false;
    const peek = tlsResponseBodyToUtf8(legacyResp).slice(0, 1600);
    return /malformed|Bad Request/i.test(peek) && /That’s an error|cannot process the request/i.test(peek);
  } catch {
    return false;
  }
}
/** curl-cffi HttpHeaders → `pc()` uyumlu düz nesne (`Set-Cookie` çok satır). */
function glifCfHeadersToPcShape(hdr) {
  const out = {};
  try {
    const M = hdr && hdr.headers;
    if (!(M instanceof Map)) return out;
    for (const [k0, vals] of M.entries()) {
      const lk = String(k0).toLowerCase();
      const keyOut = lk === 'location' ? 'Location' : lk === 'set-cookie' ? 'Set-Cookie' : String(k0);
      out[keyOut] = vals.length <= 1 ? vals[0] : vals.slice();
    }
  } catch (_) {}
  return out;
}
/** Yönlendirme zincirinden son geçerli https URL — followGet uyumu için. */
function glifCfFinalEffectiveUrl(cfRes, fallbackUrl) {
  try {
    const st = cfRes?.stacks;
    if (Array.isArray(st) && st.length) {
      for (let i = st.length - 1; i >= 0; i--) {
        const u = st[i]?.url;
        if (u && /^https?:\/\//i.test(String(u))) return String(u);
      }
    }
  } catch (_) {}
  return String(cfRes?.request?.url || cfRes?.url || fallbackUrl || '');
}
function glifCfToLegacyShape(cfRes, requestUrlFallback) {
  let buf = cfRes?.dataRaw;
  if (buf != null && !Buffer.isBuffer(buf)) {
    try {
      buf = Buffer.from(buf);
    } catch (_) {
      buf = null;
    }
  }
  if (!buf || !Buffer.isBuffer(buf)) buf = Buffer.alloc(0);
  return {
    status: Number(cfRes?.status) || 0,
    headers: glifCfHeadersToPcShape(cfRes?.headers),
    data: buf,
    finalUrl: glifCfFinalEffectiveUrl(cfRes, requestUrlFallback),
  };
}
async function glifCfPerformOnce(reqUrlStr, tlsOpts, methodUpper, impersonate) {
  const hdrs =
    tlsOpts.headers && typeof tlsOpts.headers === 'object' && !Array.isArray(tlsOpts.headers)
      ? { ...tlsOpts.headers }
      : {};
  /** TLS (impersonate) ile uyum için istekte görünür UA majörü = `glifResolvedChromeMajor()` (rrk≈46). */
  if (hdrs['User-Agent'] == null && hdrs['user-agent'] == null) hdrs['User-Agent'] = glifActiveUAChrome();
  if (process.env.GLIF_CF_INJECT_UA === '1' && tlsOpts.userAgent)
    hdrs['User-Agent'] = String(tlsOpts.userAgent);
  const pxTls = tlsOpts.proxy && String(tlsOpts.proxy).trim();
  const pxEff = (pxTls || (PROXY && String(PROXY).trim()) || undefined) ?? undefined;
  /** accounts `batchexecute` / `browserinfo`: libcurl ek Accept/Accept-Encoding bazen XHR ile çakışır — varsayılan kapalı; aç: `GLIF_CF_ACCOUNTS_RPC_MIN_HEADERS=0` */
  let defaultHeaders = process.env.GLIF_CF_DEFAULT_HEADERS === '0' ? false : true;
  try {
    const u = new URL(String(reqUrlStr));
    if (
      u.hostname === 'accounts.google.com' &&
      /batchexecute|browserinfo/i.test(u.pathname || '') &&
      process.env.GLIF_CF_ACCOUNTS_RPC_MIN_HEADERS !== '0'
    )
      defaultHeaders = false;
  } catch (_) {}
  const merged = {
    url: String(reqUrlStr),
    method: String(methodUpper || 'GET').toUpperCase(),
    headers: hdrs,
    allowRedirects: !tlsOpts.disableRedirect,
    keepAlive: false,
    impersonate: String(impersonate),
    defaultHeaders,
    curlOptions: {},
  };
  if (pxEff) merged.proxy = pxEff;
  if (tlsOpts.body != null && tlsOpts.body !== '') merged.data = tlsOpts.body;
  /**
   * curl-cffi: `opts.httpVersion` при `impersonate` игнорируется; при необходимости задаём CurlOpt ile.
   * Varsayılan: dokunma (profilün ALPN/H2 doğal akışı). `forceHTTP1` veya `GLIF_CF_FORCE_HTTP11=1` ile HTTP/1.1.
   */
  if (tlsOpts.forceHTTP1 || process.env.GLIF_CF_FORCE_HTTP11 === '1')
    merged.curlOptions[CurlOpt.HttpVersion] = CurlHttpVersion.V1_1;
  else if (process.env.CYCLETLS_H2 === '1')
    merged.curlOptions[CurlOpt.HttpVersion] = CurlHttpVersion.V2_0;
  const cfJa3 = String(process.env.GLIF_CF_JA3 || '').trim();
  if (cfJa3) merged.ja3 = cfJa3;
  return await _curlCli.request(merged);
}

function glifStripEmptyCookieHeader(h) {
  if (!h || typeof h !== 'object') return;
  for (const k of Object.keys(h))
    if (k.toLowerCase() === 'cookie' && !String(h[k] ?? '').trim()) delete h[k];
}

/** Node `fetch` → CycleTLS uyumlu nesne (GET/POST; redirect=manual ise `fallbackReqUrl`). */
async function glifNodeFetchToLegacy(reqUrlStr, tlsOpts, methodUpper, fallbackReqUrl) {
  const hdrs =
    tlsOpts.headers && typeof tlsOpts.headers === 'object' && !Array.isArray(tlsOpts.headers)
      ? { ...tlsOpts.headers }
      : {};
  glifStripEmptyCookieHeader(hdrs);
  if (hdrs['User-Agent'] == null && hdrs['user-agent'] == null) hdrs['User-Agent'] = glifActiveUAChrome();
  const meth = String(methodUpper || 'GET').toUpperCase();
  const manual = !!tlsOpts.disableRedirect;
  const init = {
    method: meth,
    redirect: manual ? 'manual' : 'follow',
    headers: hdrs,
  };
  if (meth !== 'GET' && meth !== 'HEAD' && tlsOpts.body != null && tlsOpts.body !== '')
    init.body = typeof tlsOpts.body === 'string' ? tlsOpts.body : Buffer.from(tlsOpts.body);
  const res = await fetch(reqUrlStr, init);
  const buf = Buffer.from(await res.arrayBuffer());
  const headers = {};
  const sc = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  if (Array.isArray(sc) && sc.length) headers['Set-Cookie'] = sc;
  for (const [k, v] of res.headers.entries()) {
    if (k.toLowerCase() === 'set-cookie') continue;
    headers[k] = v;
  }
  return {
    status: Number(res.status) || 0,
    headers,
    data: buf,
    finalUrl: manual ? fallbackReqUrl : String(res.url || fallbackReqUrl || ''),
  };
}

function glifHttpDebugEchoResponse(id, r, reqUrlStr) {
  if (!GLIF_HTTP_DEBUG || !r) return;
  const maxBody = GLIF_HTTP_DEBUG_VERBOSE ? 40000 : 6000;
  const { len, text, note } = glifPeekResponseChars(r, maxBody);
  console.log(
    `[http #${id} ←] status=${r.status} dataLen≈${len} final=${glifDbgShort(String(r.finalUrl || ''), 120)} ${note ? `│ ${note}` : ''}`,
  );
  const pickHdr = ['content-type', 'location', 'x-frame-options', 'cache-control'];
  if (r.headers && typeof r.headers === 'object') {
    for (const p of pickHdr) {
      const hk = Object.keys(r.headers).find(x => String(x).toLowerCase() === p);
      if (!hk || r.headers[hk] == null) continue;
      const v = Array.isArray(r.headers[hk]) ? r.headers[hk][0] : r.headers[hk];
      console.log(`       R ${hk}: ${glifDbgShort(String(v), 220)}`);
    }
    glifLogSetCookieSummary(r.headers);
  }
  const flat = typeof text === 'string' ? text : '';
  const rrkM =
    flat.match(/"?rrk"?\s*,\s*"?(\d+)"?/i)
    ?? flat.match(/\\"?rrk\\"?\s*,\s*\\"?(\d+)\\"?/i);
  if (rrkM) console.log(`       >>> Sunucu rrk=${rrkM[1]} (bu yanıtta) <<<`);
  if (/\bTL[=:]\s*|AIgtPP[^\s"',]+/i.test(flat.slice(0, 80000)))
    console.log('       not: TL / AIgtPP benzeri doku yanıtta var');
  console.log('[http #' + id + ' gövde]');
  console.log(glifSanitizeLogText(flat));
  console.log('─'.repeat(76));
}

/** `www.google.com` → sık kullanılan `NID` (proxy yok). */
async function glifPrimeNidCookie() {
  if (!GLIF_PRIME_WWW_GOOGLE || (PROXY && String(PROXY).trim())) return;
  try {
    const res = await fetch('https://www.google.com/', {
      redirect: 'follow',
      headers: {
        'User-Agent': glifActiveUAChrome(),
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9',
      },
    });
    const headers = {};
    const sc = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    if (Array.isArray(sc) && sc.length) headers['Set-Cookie'] = sc;
    pc(headers);
    await res.arrayBuffer();
    if (GLIF_HTTP_DEBUG)
      console.log(`[prime] www.google.com HTTP ${res.status} → jar: ${Object.keys(jar).join(', ') || '(boş)'}`);
  } catch (e) {
    if (GLIF_HTTP_DEBUG) console.warn('[prime] www.google.com:', e?.message || e);
  }
}

async function cycleTLS(url, opts, method) {
  const id = ++__glifHttpSeq;
  const meth = String(method || 'get').toUpperCase();
  const reqUrlStr = typeof url === 'string' ? url : String(url);
  let host = '';
  try {
    host = new URL(reqUrlStr).hostname;
  } catch {
    host = '';
  }
  const useProxyNav = !!(PROXY && String(PROXY).trim());
  const useFetchNavAccounts =
    GLIF_ACCOUNTS_NAV_FETCH && !useProxyNav && meth === 'GET' && host === 'accounts.google.com';
  const useFetchPlayLog =
    GLIF_PLAY_LOG_FETCH &&
    !useProxyNav &&
    meth === 'POST' &&
    host === 'play.google.com' &&
    /\/log\b/i.test(reqUrlStr);
  let path = '';
  try {
    path = new URL(reqUrlStr).pathname || '';
  } catch {
    path = '';
  }
  const useFetchAccountsRpc =
    GLIF_ACCOUNTS_RPC_FETCH &&
    !useProxyNav &&
    meth === 'POST' &&
    host === 'accounts.google.com' &&
    (path.includes('batchexecute') || path.includes('browserinfo'));

  const useNodeFetch =
    useFetchNavAccounts || useFetchPlayLog || useFetchAccountsRpc;

  if (GLIF_HTTP_DEBUG) {
    const uTry = reqUrlStr;
    let q = '';
    try {
      const sp = new URL(uTry).searchParams;
      if (meth === 'POST' || uTry.includes('_reqid=')) {
        const rpc = sp.get('rpcids');
        const rid = sp.get('_reqid');
        if (rpc || rid) q = ` │ rpcids=${rpc || '?'} _reqid=${rid || '?'}`;
      }
      if (uTry.includes('browserinfo')) q += ' │ browserinfo';
    } catch (_) {}
    console.log(`[http #${id} →] ${meth} ${glifDbgShort(uTry, 168)}${q}`);
    const tlsHint = useFetchNavAccounts
      ? 'transport=fetch-nav (Node TLS)'
      : useFetchPlayLog
        ? 'transport=fetch-post play.log (Node TLS)'
        : useFetchAccountsRpc
          ? 'transport=fetch-accounts-RPC (Node TLS)'
          : `cffi imp∈${glifDbgShort(glifCfRotateImpersonateOrder().join(','), 70)} pinned=${_cffiPinned || '—'}`;
    console.log(`       opts: proxy=${opts?.proxy ? glifDbgShort(String(opts.proxy), 88) : '(yok)'} disableRedirect=${!!opts?.disableRedirect} ${tlsHint}`);
    glifLogOutgoingHeaders(opts?.headers || {});
    if (opts?.body != null && opts.body !== '') {
      const bs =
        typeof opts.body === 'string' ? opts.body
        : Buffer.isBuffer(opts.body) ? opts.body.toString('utf8')
        : String(opts.body);
      console.log(`       body uzunluk=${bs.length}`);
      console.log(glifSanitizeLogText(bs));
    }
    console.log(`       jar: ${Object.keys(jar).length} çerez ismi → ${Object.keys(jar).slice(0, 28).join(', ') || '(boş)'}${Object.keys(jar).length > 28 ? ' …' : ''}`);
  }
  if (useNodeFetch) {
    try {
      const rNode = await glifNodeFetchToLegacy(reqUrlStr, opts || {}, meth, reqUrlStr);
      pc(rNode.headers);
      glifHttpDebugEchoResponse(id, rNode, reqUrlStr);
      return rNode;
    } catch (eNf) {
      if (GLIF_HTTP_DEBUG)
        console.warn(
          `[http #${id}] Node fetch başarısız — curl-cffi’ye düşülür: ${glifDbgShort(String(eNf?.message || eNf), 120)}`,
        );
    }
  }
  let lastErr = null;
  let r = null;
  const order = glifCfRotateImpersonateOrder();
  if (!order.length) throw new Error('GLIF_CF_IMPERSONATE listesi boş');
  for (let ti = 0; ti < CF_SSL_ROUND_CAP; ti++) {
    const impersonateSel = order[ti % order.length];
    try {
      const cfRes = await glifCfPerformOnce(reqUrlStr, opts || {}, meth, impersonateSel);
      const got = glifCfToLegacyShape(cfRes, reqUrlStr);
      if (glifCfGoogleMalformed400(got, reqUrlStr)) {
        _cffiPinned = '';
        r = got;
        if (GLIF_HTTP_DEBUG)
          console.warn(
            `[http #${id}] Google 400 malformed — imp=${impersonateSel} (${ti + 1}/${CF_SSL_ROUND_CAP}), sıradaki profil`,
          );
        continue;
      }
      _cffiPinned = impersonateSel;
      r = got;
      if (ti > 0 && GLIF_HTTP_DEBUG)
        console.log(`       [curl-cffi transport retry OK] tur=${ti + 1} imp=${impersonateSel}`);
      break;
    } catch (e) {
      lastErr = e;
      if (!glifCfSslRecoverable(e)) {
        if (GLIF_HTTP_DEBUG) console.error(`[http #${id} !] curl-cffi: ${e?.message || e}`);
        throw e;
      }
      _cffiPinned = '';
      if (GLIF_HTTP_DEBUG)
        console.warn(
          `[http #${id}] ssl/retry (${ti + 1}/${CF_SSL_ROUND_CAP}) imp=${impersonateSel} → ${glifDbgShort(String(e?.message || e), 100)}`,
        );
      if (ti >= CF_SSL_ROUND_CAP - 1) {
        if (GLIF_HTTP_DEBUG) console.error(`[http #${id} !] tüm Curl SSL denemeleri tükendi`);
        throw e;
      }
    }
  }
  if (!r) throw lastErr || new Error('curl-cffi: yanıtsız döndü');
  if (GLIF_HTTP_DEBUG && glifCfGoogleMalformed400(r, reqUrlStr))
    console.warn(
      `[http #${id}] tüm impersonate turlarından sonra da 400 malformed (son URL: ${glifDbgShort(reqUrlStr, 92)})`,
    );
  pc(r.headers);
  if (GLIF_HTTP_DEBUG) {
    const maxBody = GLIF_HTTP_DEBUG_VERBOSE ? 40000 : 6000;
    const { len, text, note } = glifPeekResponseChars(r, maxBody);
    console.log(`[http #${id} ←] status=${r.status} dataLen≈${len} final=${glifDbgShort(String(r.finalUrl || ''), 120)} ${note ? `│ ${note}` : ''}`);
    const pickHdr = ['content-type', 'location', 'x-frame-options', 'cache-control'];
    if (r.headers && typeof r.headers === 'object') {
      for (const p of pickHdr) {
        const hk = Object.keys(r.headers).find(x => String(x).toLowerCase() === p);
        if (!hk || r.headers[hk] == null) continue;
        const v = Array.isArray(r.headers[hk]) ? r.headers[hk][0] : r.headers[hk];
        console.log(`       R ${hk}: ${glifDbgShort(String(v), 220)}`);
      }
      glifLogSetCookieSummary(r.headers);
    }
    const flat = typeof text === 'string' ? text : '';
    const rrkM =
      flat.match(/"?rrk"?\s*,\s*"?(\d+)"?/i)
      ?? flat.match(/\\"?rrk\\"?\s*,\s*\\"?(\d+)\\"?/i);
    if (rrkM) console.log(`       >>> Sunucu rrk=${rrkM[1]} (bu yanıtta) <<<`);
    if (/\bTL[=:]\s*|AIgtPP[^\s"',]+/i.test(flat.slice(0, 80000)))
      console.log('       not: TL / AIgtPP benzeri doku yanıtta var');
    console.log('[http #' + id + ' gövde]');
    console.log(glifSanitizeLogText(flat));
    console.log('─'.repeat(76));
  }
  return r;
}
cycleTLS.exit = () => {
  try {
    _curlCli.close();
  } catch (_) {}
};

/** CycleTLS/`curl-cffi` dışında kalan `fetch` çağrıları — aynı debug bayrağı altında tek listede görünsün. */
async function glifFetch(url, init) {
  const id = ++__glifFetchSeq;
  let uShow = String(url);
  uShow = uShow.replace(/([?&]api_key=)([^&]*)/gi, '$1***');
  uShow = uShow.replace(/([?&]token=)([^&]*)/gi, '$1***');
  try {
    if (EMAIL && EMAIL.length > 4) {
      uShow = uShow.split(encodeURIComponent(EMAIL)).join('***email***');
      uShow = uShow.split(String(EMAIL)).join('***email***');
    }
  } catch (_) {}
  if (PASSWORD) uShow = uShow.split(PASSWORD).join('***pw***');
  const method = String(init?.method ?? 'GET').toUpperCase();
  if (GLIF_HTTP_DEBUG) {
    console.log(`[fetch #${id} →] ${method} ${glifDbgShort(uShow, 240)}`);
    if (init?.headers != null && typeof init.headers === 'object' && !Array.isArray(init.headers)) {
      for (const [hk, hv] of Object.entries(init.headers))
        console.log(`       fh ${hk}: ${glifDbgShort(String(hv), 140)}`);
    }
    if (init?.body != null && init.body !== '')
      console.log(`       body: ${glifSanitizeLogText(String(init.body), 1200)}`);
  }
  const r = await fetch(url, init);
  if (GLIF_HTTP_DEBUG) {
    const ct = typeof r.headers?.get === 'function' ? r.headers.get('content-type') : '';
    console.log(`[fetch #${id} ←] HTTP ${r.status} ok=${r.ok} ct=${glifDbgShort(ct || '?', 80)}`);
    if (GLIF_HTTP_DEBUG_VERBOSE) {
      try {
        const c = r.clone();
        const peek = await c.text();
        console.log(`[fetch #${id} gövde]`, glifSanitizeLogText(peek, 12000));
      } catch (e) {
        console.log(`       (yanıt klon/yazılamadı: ${e?.message || e})`);
      }
    }
    console.log('──'.repeat(38));
  }
  return r;
}

/** Kısaltılmış URL/lokasyon (terminal log için). */
function navShort(str, max = 110) {
  const s = str == null ? '' : String(str);
  return s.length > max ? `${s.slice(0, Math.max(0, max - 1))}…` : s;
}

/** Her adımda cycleTLS → Set-Cookie jar’a yazılır.
 * @param headersOrFn Obje veya `({ hop, url, startUrl }) => headers`
 * @param navDebugEtiketi Dolu ise her sıçrayı ve jar boyutunu yazar ([-1],[0b] için). */
async function followGet(startUrl, headersOrFn, maxHops = 16, navDebugEtiketi = '') {
  let u = startUrl;
  const etiket = typeof navDebugEtiketi === 'string' ? navDebugEtiketi : '';
  let lastSeenResponse;
  const resolveHdrs =
    typeof headersOrFn === 'function'
      ? ctx =>
          headersOrFn({
            hop: ctx.hop,
            url: ctx.url,
            startUrl,
          })
      : () =>
          headersOrFn;
  for (let hop = 0; hop < maxHops; hop++) {
    const headers = resolveHdrs({ hop, url: u });
    const r = await cycleTLS(u, tlsBase({ headers, disableRedirect: true }));
    lastSeenResponse = r;
    const jarN = Object.keys(jar).length;
    const lr = r.headers['Location'] || r.headers['location'];
    const loc = lr ? (Array.isArray(lr) ? lr[0] : lr) : '';
    const htmlB = typeof r.data === 'string' ? r.data.length : typeof r.data === 'object' && r.data?.length != null ? r.data.length : 0;

    if (etiket) {
      const bodyInfo = typeof r.data === 'string' ? ` yanıt~${htmlB}b` : (r.data != null ? ' yanıt=<binary>' : '');
      console.log(`  ${etiket} adım ${hop + 1}: ${r.status} ${navShort(u)}${bodyInfo}`);
      console.log(`       Cookie jar: ${jarN} anahtar`);
      if (loc)
        console.log(`       Location: ${navShort(loc, 140)}`);
      else if (r.status >= 300 && r.status < 400)
        console.log('       uyarı: 3xx ama Location başlığı yok');
      const tam = new URL(u).pathname + new URL(u).search;
      if (/interactivelogin/i.test(tam))
        console.log('       işaret: URL yolunda InteractiveLogin');
      if (/\bsignin\/identifier/i.test(tam))
        console.log('       işaret: identifier yolu içeriyor');
      if (/\bifkv=/.test(String(loc || u))) console.log('       işaret: ifkv sorgu parametresi');
    }

    if (r.status < 300 || r.status >= 400) {
      const out = r.finalUrl || u;
      if (etiket)
        console.log(`  ${etiket} → zincir durdu (${r.status}). Son URL: ${navShort(out, 140)}`);
      return { response: r, url: out };
    }
    if (!loc) {
      const out = r.finalUrl || u;
      if (etiket)
        console.log(`  ${etiket} → Location yok, durduk. Son URL: ${navShort(out, 140)}`);
      return { response: r, url: out };
    }
    u = new URL(loc, u).href;
  }
  if (etiket) console.warn(`  ${etiket} → üst limite (${maxHops}) ulaşıldı. Son: ${navShort(u, 140)}`);
  return { url: u, response: lastSeenResponse };
}
function parseDS(html,key){const m=html.indexOf(`key: '${key}'`);if(m<0)return null;const dp=html.indexOf('data:',m);const as=html.indexOf('[',dp);let d=0,p=as,s=false,e=false;for(;p<html.length;p++){const c=html[p];if(e){e=false;continue}if(c==='\\'){e=true;continue}if(c==='"'){s=!s;continue}if(s)continue;if(c==='[')d++;if(c===']'){d--;if(d===0)break}}return JSON.parse(html.substring(as,p+1).replace(/\\u003d/g,'=').replace(/\\u003c/g,'<').replace(/\\u003e/g,'>'))}

/**
 * AccountsSignInUi batchexecute / browserinfo XHR başlıkları.
 * `sec-ch-ua` / `User-Agent` / `x-browser-validation` majörü = `glifResolvedChromeMajor()` (= curl-cffi `chrome*` impersonate ile aynı; aksi MI613e’de **rrk=46**).
 */
function accountsSignInUiXHRHeaders(qz, ifkv) {
  const uaStr = glifActiveUAChrome();
  return {
    accept: '*/*',
    'accept-language': 'tr-TR,tr;q=0.6',
    'cache-control': 'no-cache',
    'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
    origin: 'https://accounts.google.com',
    pragma: 'no-cache',
    priority: 'u=1, i',
    referer: accountsGlifDocReferer,
    ...glifChromeSecChHeaders(),
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
    'x-goog-ext-391502476-jspb': JSON.stringify([qz, SERVICE, null, ifkv || null]),
    'x-same-domain': '1',
    Cookie: ck(),
  };
}

/** batchexecute (rpc) POST başlığı */
function bh(qz, ifkv) {
  return accountsSignInUiXHRHeaders(qz, ifkv);
}

/** Body içindeki brands[] sırası: `navigator.userAgentData` + sec-ch-ua ile birebir. */
function playLogJsonBody(t0, t1) {
  const mj = glifResolvedChromeMajor();
  const v = String(mj);
  const fv = `${mj}.0.0.0`;
  return `[[1,null,null,null,null,null,null,null,null,null,[null,null,null,null,"tr",null,"53",null,[[["Google Chrome","${v}"],["Chromium","${v}"],["Not_A Brand","8"]],0,"Windows","19.0.0","x86","","${fv}"],[3,0]]],1828,[[${t0},null,null,null,null,null,null,"[[[\\"/client_streamz/bg/ec\\",null,[\\"en\\",\\"mk\\"],[[[[\\"t\\"],[\\"_\\"]],[1]]]],[\\"/client_streamz/bg/el\\",null,[\\"en\\",\\"mk\\"],[[[[\\"t\\"],[\\"_\\"]],[null,326.4000000357628]]]]]]",null,null,null,null,null,null,-10800,null,null,null,null,null,1]],${t1}]]`;
}

/** play.google.com ingest: bazı çıkılışlarda `Cookie` malformed 400 yapar — başlığı tamamen sil. */
function headersStripCookieCaseInsensitive(hdrs) {
  if (!hdrs || typeof hdrs !== 'object') return hdrs;
  for (const k of Object.keys(hdrs))
    if (k.toLowerCase() === 'cookie') delete hdrs[k];
  return hdrs;
}

function harHostUsesCookie(hostname) {
  const h = hostname || '';
  if (h.endsWith('.gstatic.com') || h === 'gstatic.com' || h === 'fonts.gstatic.com') return false;
  return /\.google\.com$/i.test(h) || /\.youtube\.com$/i.test(h) || /\.googleapis\.com$/i.test(h) || /\.gvt1\.com$/i.test(h);
}

function headersFromHarRequest(entry, dropCookie = true) {
  const out = {};
  for (const { name, value } of entry.request?.headers || []) {
    const ln = name.toLowerCase();
    if (ln.startsWith(':')) continue;
    if (ln === 'content-length') continue;
    if (ln === 'host') continue;
    if (dropCookie && ln === 'cookie') continue;
    out[name] = value;
  }
  return out;
}

/** play.google.com/log ping + gstatic/fonts GET: `accountsSignInUiXHRHeaders` ile aynı sec-ch (impersonate majör ile). */
function applyChromePassiveClientHints(hdrs = {}) {
  const h =
    hdrs !== null && typeof hdrs === 'object' && !Array.isArray(hdrs)
      ? { ...hdrs }
      : {};
  Object.assign(h, glifChromeSecChHeaders());
  return h;
}

/** HAR yakalayıcıdaki sırayı koru; zamanlayıcı & e‑posta parametreleri canlı. */
function adjustHarReplayUrl(url) {
  if (typeof url !== 'string') return url;
  if (url.includes('accounts.youtube.com/accounts/CheckConnection'))
    return url.replace(/timestamp=\d+/g, () => `timestamp=${Date.now()}`);
  if (url.includes('/mail/gxlu')) {
    const nu = new URL(url);
    nu.searchParams.set('email', EMAIL);
    nu.searchParams.set('zx', String(Date.now()));
    return nu.href;
  }
  return url;
}

async function harReplayOneEntry(entry, playCtr) {
  const rawUrl = entry.request?.url;
  if (!rawUrl || typeof rawUrl !== 'string') return;
  if (rawUrl.includes('/data/batchexecute')) return;
  const url = adjustHarReplayUrl(rawUrl);
  const method = String(entry.request.method || 'GET').toLowerCase();
  let hn = '';
  try {
    const pu = new URL(url);
    hn = pu.hostname;
    /** Tarayıcı favicon indirir; CycleTLS ile www.google.com uçlarında TLS seçimi syscall 495 dönebiliyor — MI613e öncesi gürültü / risk. */
    if (/\.ico$/i.test(pu.pathname || '') && (hn === 'www.google.com' || hn === 'accounts.google.com')) return;
  } catch {
    return;
  }
  /** HAR Brave/chrome karma sec-ch ile batchexecute uyumsuztu → Chrome üçlüsüne düzelt. */
  let headers = applyChromePassiveClientHints(headersFromHarRequest(entry));
  /** Tarayıcı HAR'da play.log ping'e Cookie yok — jar eklemek sık sık HTTP 400 (Malformed) verdi. */
  const attachJarCookie = harHostUsesCookie(hn) && hn !== 'play.google.com';
  if (attachJarCookie) {
    const c = ck();
    if (c) headers['Cookie'] = c;
  }
  let body;
  const postText = entry.request.postData?.text;
  const isPlayPing = hn === 'play.google.com' && url.includes('/log') && method === 'post';

  if (isPlayPing) {
    if (process.env.GLIF_SKIP_PLAY_LOG === '1') return;
    headersStripCookieCaseInsensitive(headers);
    const base = Date.now() + ((playCtr?.ref || 0) * 41);
    if (playCtr) playCtr.ref = (playCtr.ref || 0) + 1;
    body = playLogJsonBody(base, base + 2);
    headers['Content-Type'] = 'text/plain;charset=UTF-8';
    if (!headers['Referer'] && !headers['referer']) headers['Referer'] = 'https://accounts.google.com/';
  } else if (postText != null && postText !== '' && method !== 'get' && method !== 'head') {
    body = postText;
    const mt = entry.request.postData?.mimeType;
    if (mt && !headers['Content-Type'] && !headers['content-type'])
      headers['Content-Type'] = mt;
  }
  const extras = { disableRedirect: true };
  if (body != null) extras.body = body;
  /** play.log ingest bazen HTTP/2 + CycleTLS bileşimi 400 döndürdü; HAR’da HTTP sürümü belirsiz → HTTP/1 dene. */
  if (isPlayPing) extras.forceHTTP1 = true;
  await cycleTLS(url, tlsBase({ headers, ...extras }), method);
}

/**
 * entries[lo … hi‑1]; batchexecute ve browserinfo atlanır (_reqid’li gerçek çağrılar kod üretir).
 */
async function harReplayPassiveSlice(entries, lo, hi, label = '[HAR]') {
  if (!Array.isArray(entries) || hi <= lo || lo < 0) return;
  const lim = Math.min(hi, entries.length);
  const playCtr = { ref: 0 };
  console.log(`${label}: pasif sıra [#${lo}–${lim - 1}] (${lim - lo} giriş)`);
  for (let i = lo; i < lim; i++) {
    try {
      const u = entries[i]?.request?.url || '';
      if (u.includes('/data/batchexecute')) continue;
      if (u.includes('AccountsSignInUi/browserinfo')) continue;
      await harReplayOneEntry(entries[i], playCtr);
    } catch (_) {
      console.warn(`${label}: atlandı idx=${i}`);
    }
  }
}

/** UEkKwb sonrası HAR eksik kalırsa kısaltılmış “19–22” sırası. */
async function fallbackPostUeKPassive() {
  const tok = [...crypto.randomBytes(4)].map(b => ('0' + b.toString(16)).slice(-2)).join('');
  await cycleTLS(`https://accounts.google.com/generate_204?${tok}`, tlsBase({
    headers: { Accept: '*/*', Cookie: ck(), 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'no-cors' },
  })).catch(() => {});
  if (process.env.GLIF_SKIP_PLAY_LOG === '1') return;
  const pu = 'https://play.google.com/log?hasfast=true&authuser=0&format=json';
  const z = Date.now();
  const playHdr = applyChromePassiveClientHints({
    'Content-Type': 'text/plain;charset=UTF-8',
    Referer: 'https://accounts.google.com/',
  });
  headersStripCookieCaseInsensitive(playHdr);
  await cycleTLS(pu, tlsBase({ body: playLogJsonBody(z, z + 2), headers: playHdr, forceHTTP1: true }), 'post').catch(() => {});
  await cycleTLS(pu, tlsBase({ body: playLogJsonBody(z + 35, z + 37), headers: playHdr, forceHTTP1: true }), 'post').catch(() => {});
}

/** Şifre aralığı için HAR slice yoksa: gxlu → generate_204 → iki play.log (HAR sırasına yakın). */
async function fallbackPreB4Passive() {
  await cycleTLS(`https://mail.google.com/mail/gxlu?email=${encodeURIComponent(EMAIL)}&zx=${Date.now()}`, tlsBase({
    headers: { Accept: 'image/avif', 'Accept-Language': 'tr-TR,tr;q=0.9', Cookie: ck(), Referer: 'https://accounts.google.com/', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'no-cors', 'Sec-Fetch-Site': 'cross-site' },
  })).catch(() => {});
  await fallbackPostUeKPassive();
}

function parseHarIndices(entries) {
  const out = {};
  if (!Array.isArray(entries)) return out;
  out.id = entries.findIndex(
    e => e._resourceType === 'document' && Number(e.response?.status) === 200 &&
      typeof e.request?.url === 'string' &&
      /\/(?:v\d+\/)?signin\/identifier/.test(e.request.url)
  );
  out.u = entries.findIndex(e => e.request?.url?.includes('rpcids=UEkKwb'));
  out.bi = entries.findIndex(e => e.request?.url?.includes('AccountsSignInUi/browserinfo'));
  out.mi = entries.findIndex(e => e.request?.url?.includes('rpcids=MI613e'));
  out.wz = entries.findIndex(e => e.request?.url?.includes('rpcids=WZfWSd'));
  out.b4 = entries.findIndex(e => e.request?.url?.includes('rpcids=B4hajb'));
  return out;
}

function loadHarEntries() {
  if (process.env.GLIF_SKIP_HAR_REPLAY === '1') return null;
  const hp = process.env.GLIF_HAR_PATH || DEFAULT_GLIF_HAR;
  try {
    if (!fs.existsSync(hp)) {
      console.warn('[HAR] dosya yok:', hp);
      return null;
    }
    const j = JSON.parse(fs.readFileSync(hp, 'utf8'));
    return j?.log?.entries || null;
  } catch (e) {
    console.warn('[HAR] okuma hatası:', e?.message || e);
    return null;
  }
}

/**
 * Glif binds the VM token to the identifier via asyncSnapshot first arg.
 * @see test_correct_binding.mjs — args [{Ko:{replayKey}}, …] to asyncSnapshotFunction.
 * Env GLIF_REPLAY: `ko` (default) | `flat` = {replayKey} only, for A/B.
 */
function glifContentBinding() {
  /** Default: same as MI613e[1] (local part for @gmail.com). GLIF_REPLAY_KEY=full uses whole address. */
  const key =
    process.env.GLIF_REPLAY_KEY === 'full' ? String(EMAIL).trim() : signinIdentifierLocalPart(EMAIL);
  const mode = process.env.GLIF_REPLAY || 'ko';
  if (mode === 'flat') return { replayKey: key };
  return { Ko: { replayKey: key } };
}

/**
 * harden(win) — install fingerprint shims so BotGuard's environment probes
 * (canvas, webgl, audio, chrome.runtime, plugins, permissions) return real
 * Chrome-shaped values instead of happy-dom defaults. Verified via
 * trace_login_bg.mjs: with these shims the BG token grows from ~1100b to
 * ~2225b (HAR truth ≈2598b), the missing 1.1kB lives in tag 0x99 (main_hash).
 */
function harden(win) {
  const fp = _babloFP || {};
  const wgp = fp.webgl_properties || {};
  const ap = fp.audio_properties || {};
  const canvasHex = fp.canvas || '';
  const webglHex = fp.webgl || '';
  const audioHex = fp.audio || '';
  if (BG_TRACE) console.log(`[harden] fp keys: ${Object.keys(fp).join(', ')}\n  canvas=${canvasHex.length}ch webgl=${webglHex.length}ch audio=${audioHex.length}ch\n  wgp keys: ${Object.keys(wgp).join(', ')}\n  ap keys: ${Object.keys(ap).join(', ')}`);
  const canvasBytes = canvasHex ? Buffer.from(canvasHex, 'hex') : null;
  const webglBytes = webglHex ? Buffer.from(webglHex, 'hex') : null;
  const audioBytes = audioHex ? Buffer.from(audioHex, 'hex') : null;
  const fontList = fp.fonts || [];
  const heapLimit = Number(fp.heap) || 4294705152;
  const heapCorr = Number(fp.heap_correction) || 0;
  const storageQuota = Number(fp.storage) || 299237373542;

  const Cproto = win.HTMLCanvasElement?.prototype;
  if (BG_TRACE) console.log(`[harden] HTMLCanvasElement.prototype = ${Cproto ? 'EXISTS' : 'MISSING'}`);
  if (Cproto) {
    const origGetContext = Cproto.getContext;
    if (BG_TRACE) console.log(`[harden] origGetContext = ${typeof origGetContext}`);
    Cproto.toDataURL = native(function toDataURL(mime) {
      if (BG_TRACE) console.log(`[canvas] toDataURL("${mime}") on ${this.width}x${this.height}`);
      const w = this.width || 1, h = this.height || 1;
      const len = w * h * 4;
      const buf = Buffer.alloc(len);
      if (canvasBytes) { for (let i = 0; i < len; i++) buf[i] = canvasBytes[i % canvasBytes.length]; }
      else { const seed = w * 31 + h * 17; for (let i = 0; i < len; i++) buf[i] = (i * 7 + seed) & 0xff; }
      return `data:${mime || 'image/png'};base64,` + buf.toString('base64');
    }, 'toDataURL');
    Cproto.getContext = function getContext(kind) {
      if (BG_TRACE) console.log(`[harden] getContext("${kind}") called on canvas ${this.width}x${this.height}`);
      if (kind === 'webgl' || kind === 'webgl2' || kind === 'experimental-webgl') {
        if (this._glCtx) return this._glCtx;
        if (this._2dCtx) return null;
        const extList = wgp.extensions || ['ANGLE_instanced_arrays','EXT_blend_minmax','EXT_color_buffer_half_float','EXT_disjoint_timer_query','EXT_float_blend','EXT_frag_depth','EXT_shader_texture_lod','EXT_texture_compression_bptc','EXT_texture_compression_rgtc','EXT_texture_filter_anisotropic','OES_element_index_uint','OES_fbo_render_mipmap','OES_standard_derivatives','OES_texture_float','OES_texture_float_linear','OES_texture_half_float','OES_texture_half_float_linear','OES_vertex_array_object','WEBGL_color_buffer_float','WEBGL_compressed_texture_s3tc','WEBGL_compressed_texture_s3tc_srgb','WEBGL_debug_renderer_info','WEBGL_debug_shaders','WEBGL_depth_texture','WEBGL_draw_buffers','WEBGL_lose_context','WEBGL_multi_draw'];
        const ctx = {
          canvas: this, drawingBufferWidth: fp.width || 1920, drawingBufferHeight: fp.height || 1080,
          getParameter(p) {
            if (BG_TRACE) console.log(`[gl] getParameter(${p})`);
            if (p === 37445) return wgp.unmaskedVendor || 'Google Inc. (Intel)';
            if (p === 37446) return wgp.unmaskedRenderer || 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            if (p === 7937)  return wgp.renderer || 'WebKit WebGL';
            if (p === 7938)  return wgp.version || 'WebGL 1.0 (OpenGL ES 2.0 Chromium)';
            if (p === 35724) return wgp.shadingLanguage || 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)';
            if (p === 3379)  return wgp.maxTextureSize || 16384;
            if (p === 34076) return wgp.maxCubeMapTextureSize || 16384;
            if (p === 36347) return wgp.maxVertexUniformVectors || 1024;
            if (p === 36348) return wgp.maxVaryingVectors || 30;
            if (p === 36349) return wgp.maxFragmentUniformVectors || 1024;
            if (p === 34930) return wgp.maxTextureImageUnits || 16;
            if (p === 34024) return wgp.maxRenderBufferSize || 16384;
            if (p === 34921) return wgp.maxVertexAttribs || 16;
            if (p === 35660) return wgp.maxVertexTextureImageUnits || 16;
            if (p === 35661) return wgp.maxCombinedTextureImageUnits || 32;
            if (p === 3408)  return wgp.stencilBits || 0;
            if (p === 3413)  return wgp.subpixelBits || 4;
            if (p === 3411)  return wgp.depthBits || 24;
            if (p === 3410)  return wgp.blueBits || 8;
            if (p === 3412)  return wgp.greenBits || 8;
            if (p === 3409)  return wgp.redBits || 8;
            if (p === 3414)  return wgp.alphaBits || 8;
            if (p === 34852) return wgp.sampleBuffers || 0;
            if (p === 36183) return wgp.maxAnisotropy ? Number(wgp.maxAnisotropy) : 16;
            if (BG_TRACE) console.log(`[gl] getParameter(${p}) → UNHANDLED, returning 0`);
            return 0;
          },
          getExtension(n) {
            if (BG_TRACE) console.log(`[gl] getExtension("${n}")`);
            return n === 'WEBGL_debug_renderer_info' ? { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 } : n === 'EXT_texture_filter_anisotropic' ? { MAX_TEXTURE_MAX_ANISOTROPY_EXT: 36183 } : {};
          },
          getSupportedExtensions() { return Array.isArray(extList) ? extList : []; },
          getShaderPrecisionFormat(st, pt) {
            if (BG_TRACE) console.log(`[gl] getShaderPrecisionFormat(${st}, ${pt})`);
            return { rangeMin: wgp.rangeMinVertexShaderHighFloat || 127, rangeMax: wgp.rangeMaxVertexShaderHighFloat || 127, precision: wgp.precisionVertexShaderHighFloat || 23 };
          },
          getContextAttributes() { return wgp.webglContextAttributesDefaults || { alpha: true, antialias: true, depth: true, premultipliedAlpha: true, stencil: false }; },
          createBuffer() { return {}; }, bindBuffer() {}, bufferData() {}, createProgram() { return {}; }, createShader() { return {}; },
          shaderSource() {}, compileShader() {}, getShaderParameter() { return true; }, attachShader() {}, linkProgram() {}, getProgramParameter() { return true; },
          useProgram() {}, getAttribLocation() { return 0; }, enableVertexAttribArray() {}, vertexAttribPointer() {},
          getUniformLocation() { return {}; }, uniform1f() {}, uniform2f() {}, uniform3f() {}, uniform4f() {},
          drawArrays() {}, drawElements() {}, viewport() {}, clear() {}, clearColor() {}, enable() {}, disable() {},
          blendFunc() {}, depthFunc() {}, scissor() {}, colorMask() {}, lineWidth() {},
          createTexture() { return {}; }, bindTexture() {}, texImage2D() {}, texParameteri() {},
          activeTexture() {}, generateMipmap() {}, pixelStorei() {},
          createFramebuffer() { return {}; }, bindFramebuffer() {}, framebufferTexture2D() {},
          checkFramebufferStatus() { return 36053; },
          readPixels(x, y, w, h, fmt, type, pixels) {
            if (BG_TRACE) console.log(`[gl] readPixels(${x},${y},${w},${h})`);
            if (pixels && webglBytes) { for (let i = 0; i < pixels.length; i++) pixels[i] = webglBytes[i % webglBytes.length]; } else if (pixels) { for (let i = 0; i < pixels.length; i++) pixels[i] = (i * 7 + 42) & 0xff; }
          },
          isContextLost() { return false; },
        };
        for (const k of Object.keys(ctx)) if (typeof ctx[k] === 'function') native(ctx[k], k);
        this._glCtx = ctx;
        return ctx;
      }
      if (this._2dCtx) return this._2dCtx;
      if (this._glCtx) return null;
      const ctx2d = {
        canvas: this,
        fillStyle: '#000000', strokeStyle: '#000000', lineWidth: 1, font: '10px sans-serif',
        textAlign: 'start', textBaseline: 'alphabetic', globalAlpha: 1, globalCompositeOperation: 'source-over',
        fillRect() {}, fillText() { if (BG_TRACE) console.log(`[2d] fillText("${arguments[0]}")`); },
        beginPath() {}, closePath() {}, fill() {}, stroke() {},
        moveTo() {}, lineTo() {}, arc() {}, rect() {}, clearRect() {}, save() {}, restore() {},
        scale() {}, rotate() {}, translate() {}, drawImage() {}, setTransform() {}, transform() {},
        measureText: (s) => ({ width: (s ? s.length : 0) * 6, actualBoundingBoxAscent: 8, actualBoundingBoxDescent: 2 }),
        getImageData: (x, y, w, h) => { if (BG_TRACE) console.log(`[2d] getImageData(${x},${y},${w},${h})`); const sz = Math.max(1, w|0) * Math.max(1, h|0) * 4; const d = new Uint8ClampedArray(sz); if (canvasBytes) { for (let i = 0; i < sz; i++) d[i] = canvasBytes[i % canvasBytes.length]; } return { data: d, width: Math.max(1, w|0), height: Math.max(1, h|0) }; },
        putImageData() {},
        createLinearGradient: () => ({ addColorStop() {} }),
        createRadialGradient: () => ({ addColorStop() {} }),
        createPattern: () => null,
      };
      for (const k of Object.keys(ctx2d)) if (typeof ctx2d[k] === 'function') native(ctx2d[k], k);
      this._2dCtx = ctx2d;
      return ctx2d;
    };
  }
  const sampleRate = ap.BaseAudioContextSampleRate || 44100;
  win.AudioContext = win.AudioContext || class { constructor() { if (BG_TRACE) console.log('[audio] new AudioContext()'); this.state = 'running'; this.sampleRate = sampleRate; this.destination = { channelCount: ap.AudioDestinationNodeMaxChannelCount || 2 }; this.currentTime = 0; this.baseLatency = ap.AudioContextBaseLatency || 0.01; this.outputLatency = ap.AudioContextOutputLatency || 0; }
    createOscillator() { return { connect() {}, start() {}, stop() {}, disconnect() {}, frequency: { value: ap.OscillatorNodeFrequencyDefaultValue || 440, setValueAtTime() {} }, type: ap.OscillatorNodeType || 'sine' }; }
    createAnalyser() { return { fftSize: ap.AnalyzerNodeFftSize || 2048, frequencyBinCount: ap.AnalyzerNodeFrequencyBinCount || 1024, minDecibels: ap.AnalyzerNodeMinDecibels || -100, maxDecibels: ap.AnalyzerNodeMaxDecibels || -30, smoothingTimeConstant: ap.AnalyzerNodeSmoothingTimeConstant || 0.8, getFloatFrequencyData(a) { if (audioBytes) { for (let i = 0; i < a.length; i++) a[i] = -100 + (audioBytes[i % audioBytes.length] / 255) * 70; } else { for (let i = 0; i < a.length; i++) a[i] = -100 + (i % 17); } }, getByteFrequencyData(a) { if (audioBytes) { for (let i = 0; i < a.length; i++) a[i] = audioBytes[i % audioBytes.length]; } else { for (let i = 0; i < a.length; i++) a[i] = (i * 3) & 0xff; } }, connect() {}, disconnect() {} }; }
    createBuffer(ch, len, sr) { return { getChannelData: () => { const a = new Float32Array(len || 2048); if (audioBytes) { for (let i = 0; i < a.length; i++) a[i] = (audioBytes[i % audioBytes.length] - 128) / 128; } return a; }, duration: (len||2048) / (sr||sampleRate), length: len||2048, numberOfChannels: ch||2, sampleRate: sr||sampleRate }; }
    createBufferSource() { return { connect() {}, disconnect() {}, start() {}, stop() {}, buffer: null }; }
    createDynamicsCompressor() { return { connect() {}, disconnect() {}, threshold: { value: ap.DynamicsCompressorNodeThresholdDefaultValue || -24, setValueAtTime() {} }, knee: { value: ap.DynamicsCompressorNodeKneeDefaultValue || 30, setValueAtTime() {} }, ratio: { value: ap.DynamicsCompressorNodeRatioDefaultValue || 12, setValueAtTime() {} }, attack: { value: ap.DynamicsCompressorNodeAttackDefaultValue || 0.003, setValueAtTime() {} }, release: { value: ap.DynamicsCompressorNodeReleaseDefaultValue || 0.25, setValueAtTime() {} }, reduction: ap.DynamicsCompressorNodeReduction || 0 }; }
    createGain() { return { connect() {}, disconnect() {}, gain: { value: ap.GainNodeGainDefaultValue || 1, setValueAtTime() {} } }; }
    createScriptProcessor() { return { connect() {}, disconnect() {}, onaudioprocess: null }; }
    createBiquadFilter() { return { connect() {}, disconnect() {}, type: ap.BiquadFilterNodeType || 'lowpass', frequency: { value: ap.BiquadFilterNodeFrequencyDefaultValue || 350, setValueAtTime() {} }, Q: { value: ap.BiquadFilterNodeQDefaultValue || 1, setValueAtTime() {} }, gain: { value: ap.BiquadFilterNodeGainDefaultValue || 0, setValueAtTime() {} }, detune: { value: ap.BiquadFilterNodeDetuneDefaultValue || 0, setValueAtTime() {} } }; }
    close() { return Promise.resolve(); }
    resume() { return Promise.resolve(); }
    decodeAudioData() { return Promise.resolve({ getChannelData: () => new Float32Array(1024), duration: 1, length: 44100, numberOfChannels: 2, sampleRate }); }
  };
  win.OfflineAudioContext = win.OfflineAudioContext || class { constructor(channels, length, sr) { this.numberOfChannels = channels || 2; this.length = length || 44100; this.sampleRate = sr || sampleRate; this.destination = { channelCount: channels || 2 }; this.currentTime = 0; }
    startRendering() { const len = this.length; return Promise.resolve({ getChannelData: () => { const a = new Float32Array(len); if (audioBytes) { for (let i = 0; i < len; i++) a[i] = (audioBytes[i % audioBytes.length] - 128) / 128 * 0.5; } else { for (let i = 0; i < Math.min(len, 1024); i++) a[i] = Math.sin(i * 0.01) * 0.3; } return a; }, duration: len / this.sampleRate, length: len, numberOfChannels: this.numberOfChannels, sampleRate: this.sampleRate }); }
    createOscillator() { return { connect() {}, disconnect() {}, start() {}, stop() {}, frequency: { value: ap.OscillatorNodeFrequencyDefaultValue || 440, setValueAtTime() {} }, type: 'triangle' }; }
    createDynamicsCompressor() { return { connect() {}, disconnect() {}, threshold: { value: ap.DynamicsCompressorNodeThresholdDefaultValue || -24, setValueAtTime() {} }, knee: { value: ap.DynamicsCompressorNodeKneeDefaultValue || 30, setValueAtTime() {} }, ratio: { value: ap.DynamicsCompressorNodeRatioDefaultValue || 12, setValueAtTime() {} }, attack: { value: ap.DynamicsCompressorNodeAttackDefaultValue || 0.003, setValueAtTime() {} }, release: { value: ap.DynamicsCompressorNodeReleaseDefaultValue || 0.25, setValueAtTime() {} } }; }
    createGain() { return { connect() {}, disconnect() {}, gain: { value: 1, setValueAtTime() {} } }; }
  };
  if (!win.document.fonts) {
    const fl = fontList;
    win.document.fonts = { check: (font) => { const fam = (font || '').replace(/^[\d.]+\w+\s+/, '').replace(/['"]/g, ''); return fl.length ? fl.some(f => f.toLowerCase() === fam.toLowerCase()) : true; }, ready: Promise.resolve(), forEach: () => {}, size: fl.length || 24, [Symbol.iterator]: function* () {} };
  }
  try { if (win.performance?.memory) Object.defineProperty(win.performance, 'memory', { get: () => ({ jsHeapSizeLimit: heapLimit, totalJSHeapSize: heapLimit + heapCorr - 4000000, usedJSHeapSize: heapLimit + heapCorr - 8000000 }), configurable: true }); } catch {}
  try { if (win.navigator?.storage?.estimate) win.navigator.storage.estimate = () => Promise.resolve({ quota: storageQuota, usage: 0 }); } catch {}

  const codecDB = fp.codecs || {};
  const HMEproto = win.HTMLMediaElement?.prototype;
  if (HMEproto && !HMEproto.canPlayType) {
    HMEproto.canPlayType = native(function canPlayType(mime) {
      if (BG_TRACE) console.log(`[media] canPlayType("${mime}")`);
      if (codecDB[mime] !== undefined) return codecDB[mime];
      if (/^(audio|video)\/(mp4|webm|ogg|mpeg|mp3|wav|flac)/i.test(mime)) return 'probably';
      if (/^(audio|video)\//i.test(mime)) return 'maybe';
      return '';
    }, 'canPlayType');
  }
  const HAproto = win.HTMLAudioElement?.prototype;
  if (HAproto && !HAproto.canPlayType) {
    HAproto.canPlayType = native(function canPlayType(mime) {
      if (BG_TRACE) console.log(`[audio-el] canPlayType("${mime}")`);
      if (codecDB[mime] !== undefined) return codecDB[mime];
      if (/^audio\/(mp4|webm|ogg|mpeg|mp3|wav|flac|aac)/i.test(mime)) return 'probably';
      if (/^audio\//i.test(mime)) return 'maybe';
      return '';
    }, 'canPlayType');
  }
  const HVproto = win.HTMLVideoElement?.prototype;
  if (HVproto && !HVproto.canPlayType) {
    HVproto.canPlayType = native(function canPlayType(mime) {
      if (BG_TRACE) console.log(`[video-el] canPlayType("${mime}")`);
      if (codecDB[mime] !== undefined) return codecDB[mime];
      if (/^video\/(mp4|webm|ogg)/i.test(mime)) return 'probably';
      if (/^video\//i.test(mime)) return 'maybe';
      return '';
    }, 'canPlayType');
  }

  function maskDeep(obj, visited) {
    if (!obj || typeof obj !== 'object' || (visited && visited.has(obj))) return;
    if (!visited) visited = new WeakSet();
    visited.add(obj);
    for (const k of Object.getOwnPropertyNames(obj)) {
      try {
        const desc = Object.getOwnPropertyDescriptor(obj, k);
        if (desc && typeof desc.value === 'function') native(desc.value, k);
        if (desc && typeof desc.get === 'function') native(desc.get, 'get ' + k);
      } catch {}
    }
  }
  if (Cproto) { maskDeep(Cproto); }
  if (win.AudioContext) { maskDeep(win.AudioContext.prototype); }
  if (win.OfflineAudioContext) { maskDeep(win.OfflineAudioContext.prototype); }
  maskDeep(win.document?.fonts);
}

function shimNav(nav) {
  const props = {
    /** Açık `false`; `undefined` bazı BG yollarında otomasyon sinyali olarak ayrılır */
    webdriver: false,
    vendor: 'Google Inc.',
    vendorSub: '',
    platform: 'Win32',
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    languages: ['tr-TR', 'tr'],
    product: 'Gecko',
    productSub: '20030107',
    appName: 'Netscape',
    appCodeName: 'Mozilla',
    cookieEnabled: true,
    onLine: true,
    doNotTrack: null,
    language: 'tr-TR',
    pdfViewerEnabled: true,
    connection: { effectiveType: '4g', downlink: 10, rtt: 50, saveData: false },
  };
  for (const [k, v] of Object.entries(props))
    Object.defineProperty(nav, k, { get: () => v, configurable: true });
  Object.defineProperty(nav, 'userAgent', { configurable: true, get: () => glifActiveUAChrome() });
  Object.defineProperty(nav, 'appVersion', {
    configurable: true,
    get: () => glifActiveUAChrome().replace(/^Mozilla\//, ''),
  });
  Object.defineProperty(nav, 'permissions', { configurable: true, get: () => ({ query: ({ name }) => Promise.resolve({ state: name === 'notifications' ? 'denied' : 'granted', onchange: null }) }) });
  Object.defineProperty(nav, 'plugins', { configurable: true, get: () => { const a = [{ name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }, { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }, { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }, { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }, { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }]; a.namedItem = (n) => a.find(p => p.name === n) || null; a.item = (i) => a[i] || null; a.refresh = () => {}; Object.defineProperty(a, 'length', { value: a.length }); return a; } });
  Object.defineProperty(nav, 'mimeTypes', { configurable: true, get: () => { const m = [{ type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }]; m.namedItem = (n) => m.find(x => x.type === n) || null; m.item = (i) => m[i] || null; return m; } });
  Object.defineProperty(nav, 'mediaDevices', { configurable: true, get: () => ({ enumerateDevices: () => Promise.resolve([]), getUserMedia: () => Promise.reject(new Error('NotAllowedError')) }) });
  Object.defineProperty(nav, 'getBattery', { configurable: true, get: () => () => Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1, addEventListener: () => {} }) });
  Object.defineProperty(nav, 'getGamepads', { configurable: true, get: () => () => [] });
  Object.defineProperty(nav, 'sendBeacon', { configurable: true, get: () => () => true });
  /** `userAgentData` majörü = `glifResolvedChromeMajor()` — batchexecute ile tutarlı. */
  Object.defineProperty(nav, 'userAgentData', {
    configurable: true,
    get: () => {
      const mj = glifResolvedChromeMajor();
      const v = String(mj);
      const fv = `${mj}.0.0.0`;
      return {
        brands: [
          { brand: 'Google Chrome', version: v },
          { brand: 'Chromium', version: v },
          { brand: 'Not_A Brand', version: '8' },
        ],
        mobile: false,
        platform: 'Windows',
        getHighEntropyValues: () =>
          Promise.resolve({
            architecture: 'x86',
            bitness: '64',
            brands: [
              { brand: 'Google Chrome', version: v },
              { brand: 'Chromium', version: v },
              { brand: 'Not_A Brand', version: '8' },
            ],
            fullVersionList: [
              { brand: 'Google Chrome', version: fv },
              { brand: 'Chromium', version: fv },
              { brand: 'Not_A Brand', version: '8.0.0.0' },
            ],
            mobile: false,
            model: '',
            platform: 'Windows',
            platformVersion: '19.0.0',
            uaFullVersion: fv,
          }),
      };
    },
  });
  Object.defineProperty(nav, 'scheduling', { configurable: true, get: () => ({ isInputPending: () => false }) });
  Object.defineProperty(nav, 'storage', { configurable: true, get: () => ({ estimate: () => Promise.resolve({ quota: 300e9, usage: 0 }) }) });
  Object.defineProperty(nav, 'keyboard', { configurable: true, get: () => ({ getLayoutMap: () => Promise.resolve(new Map()) }) });
  Object.defineProperty(nav, 'credentials', { configurable: true, get: () => ({ get: () => Promise.resolve(null), create: () => Promise.resolve(null) }) });
  Object.defineProperty(nav, 'clipboard', { configurable: true, get: () => ({ readText: () => Promise.reject(), writeText: () => Promise.resolve() }) });
  Object.defineProperty(nav, 'locks', { configurable: true, get: () => ({ request: () => Promise.resolve(), query: () => Promise.resolve({ held: [], pending: [] }) }) });
  Object.defineProperty(nav, 'globalPrivacyControl', { configurable: true, get: () => false });
  Object.defineProperty(nav, 'userActivation', {
    configurable: true,
    get: () => ({ hasBeenActive: true, isActive: false }),
  });
}

/** Intl saat dilimi BG ortam probları için (accept-language tr iken IST makul); `TZ` ile de geçilir. */
function shimIntlDateTimeTimeZone(win) {
  const I = win.Intl;
  if (!I?.DateTimeFormat || I.__glifTzBound) return;
  const TZ = String(process.env.GLIF_BG_TZ || process.env.TZ || 'Europe/Istanbul').trim();
  if (!TZ) return;
  const Base = I.DateTimeFormat;
  function PatchedDateTimeFormat(...args) {
    const dtf = Reflect.construct(Base, args, PatchedDateTimeFormat);
    const origRO = Function.prototype.bind.call(Base.prototype.resolvedOptions, dtf);
    Object.defineProperty(dtf, 'resolvedOptions', {
      configurable: true,
      writable: true,
      value() {
        try {
          const o = origRO();
          return { ...o, timeZone: TZ };
        } catch {
          return { locale: 'tr-TR', calendar: 'gregory', numberingSystem: 'latn', timeZone: TZ };
        }
      },
    });
    return dtf;
  }
  PatchedDateTimeFormat.prototype = Base.prototype;
  Object.defineProperty(PatchedDateTimeFormat, 'prototype', {
    writable: false,
    configurable: false,
    value: Base.prototype,
  });
  Object.assign(PatchedDateTimeFormat, Base);
  I.DateTimeFormat = PatchedDateTimeFormat;
  I.__glifTzBound = true;
}

/** bgutils `vm.a(..., userInteractionElement, ...)`: happy-dom ile DOM düğümü bağla; layout probları için getBoundingClientRect. */
function bgUserInteractionStub(win) {
  if (process.env.GLIF_BG_NO_UI_STUB === '1') return undefined;
  try {
    const el = win.document.createElement('button');
    el.type = 'submit';
    const rect = Object.freeze({
      x: 640, y: 420, width: 120, height: 44, top: 420, left: 640, right: 760, bottom: 464,
    });
    Object.defineProperty(el, 'offsetWidth', { get: () => 120, configurable: true });
    Object.defineProperty(el, 'offsetHeight', { get: () => 44, configurable: true });
    el.getBoundingClientRect = () => ({ ...rect, toJSON: () => ({ ...rect }) });
    try {
      el.focus = Object.getPrototypeOf(Object.getPrototypeOf(el)).focus ?? (() => {});
    } catch (_) {}
    return el;
  } catch (_) {
    return undefined;
  }
}

const _nativeMasked = new WeakSet();
function native(fn, name) {
  if (typeof fn === 'function') {
    _nativeMasked.add(fn);
    if (name) try { Object.defineProperty(fn, 'name', { value: name, configurable: true }); } catch {}
  }
  return fn;
}

function shimWindow(w) {
  const origToString = w.Function.prototype.toString;
  w.Function.prototype.toString = function () {
    if (_nativeMasked.has(this)) return `function ${this.name || ''}() { [native code] }`;
    return origToString.call(this);
  };
  _nativeMasked.add(w.Function.prototype.toString);

  // ── Error().stack sanitization: Node.js paths → Chrome-like URLs ──
  const OrigError = w.Error;
  const fakeOrigin = 'https://accounts.google.com';
  function sanitizeStack(stack) {
    if (typeof stack !== 'string') return stack;
    return stack
      .replace(/\(node:internal\/[^\)]+\)/g, '(<anonymous>)')
      .replace(/\(eval at [^,]+, [^\)]+\)/g, '(eval at <anonymous>)')
      .replace(/at\s+file:\/\/\/[^\s]+/g, `at ${fakeOrigin}/v3/signin/identifier`)
      .replace(/at\s+[A-Za-z]:\\[^\s\)]+/g, `at ${fakeOrigin}/v3/signin/identifier`)
      .replace(/at\s+\/[^\s\)]+\.m?js[:\d]*/g, `at ${fakeOrigin}/v3/signin/identifier`)
      .replace(/\([A-Za-z]:\\[^\)]+\)/g, `(${fakeOrigin}/v3/signin/identifier:1:1)`)
      .replace(/\(\/[^\)]+\.m?js[^\)]*\)/g, `(${fakeOrigin}/v3/signin/identifier:1:1)`)
      .replace(/node:internal\/[^\s\):]*/g, '<anonymous>');
  }
  w.Error = function (...args) {
    const err = new OrigError(...args);
    const origStack = err.stack;
    Object.defineProperty(err, 'stack', {
      get: () => sanitizeStack(origStack),
      set: (v) => { origStack = v; },
      configurable: true,
    });
    return err;
  };
  w.Error.prototype = OrigError.prototype;
  w.Error.captureStackTrace = OrigError.captureStackTrace
    ? function(target, ctor) {
        OrigError.captureStackTrace(target, ctor);
        const raw = target.stack;
        Object.defineProperty(target, 'stack', {
          get: () => sanitizeStack(raw),
          configurable: true,
        });
      }
    : undefined;
  w.Error.stackTraceLimit = OrigError.stackTraceLimit;
  // Intercept prepareStackTrace: BG may use it to get raw CallSite objects with getFileName()
  Object.defineProperty(w.Error, 'prepareStackTrace', {
    configurable: true,
    set(fn) {
      if (typeof fn !== 'function') { this._pst = fn; return; }
      this._pst = function(err, callSites) {
        const faked = callSites.map(cs => {
          const orig = cs;
          return new Proxy(cs, {
            get(t, prop) {
              if (prop === 'getFileName') return () => `${fakeOrigin}/v3/signin/identifier`;
              if (prop === 'getScriptNameOrSourceURL') return () => `${fakeOrigin}/v3/signin/identifier`;
              if (prop === 'getEvalOrigin') return () => `${fakeOrigin}/v3/signin/identifier`;
              if (prop === 'isNative') return () => false;
              const v = Reflect.get(t, prop);
              return typeof v === 'function' ? v.bind(t) : v;
            }
          });
        });
        return fn(err, faked);
      };
    },
    get() { return this._pst; },
  });
  for (const sub of ['TypeError', 'RangeError', 'ReferenceError', 'SyntaxError', 'URIError', 'EvalError']) {
    if (w[sub]) {
      const Orig = w[sub];
      w[sub] = function(...args) {
        const e = new Orig(...args);
        const raw = e.stack;
        Object.defineProperty(e, 'stack', { get: () => sanitizeStack(raw), configurable: true });
        return e;
      };
      w[sub].prototype = Orig.prototype;
    }
  }

  // ── Node.js global leak prevention ──
  for (const g of ['process', 'global', 'globalThis', 'require', 'module', '__dirname', '__filename', 'Buffer']) {
    try { Object.defineProperty(w, g, { get: () => undefined, set: () => {}, configurable: true }); } catch {}
  }
  // Kill setImmediate — BG uses requestIdleCallback→setImmediate→setTimeout chain;
  // taking setImmediate path = Node.js signal
  try { Object.defineProperty(w, 'setImmediate', { get: () => undefined, configurable: true }); } catch {}

  // ── Object.prototype.toString → [object Window] for the window object ──
  try {
    const _origObjToStr = Object.prototype.toString;
    const _winRef = w;
    Object.defineProperty(w, Symbol.toStringTag, { get: () => 'Window', configurable: true });
  } catch {}

  // ── Ensure document.body exists (BG appends hidden iframes to it) ──
  try {
    if (!w.document.body) {
      const body = w.document.createElement('body');
      w.document.documentElement?.appendChild(body);
    }
  } catch {}

  shimNav(w.navigator);
  try { shimIntlDateTimeTimeZone(w); } catch (_) {}
  try { w.crypto.getRandomValues = native(a => { crypto.randomFillSync(a); return a; }, 'getRandomValues'); } catch {}
  try {
    Object.defineProperty(w.document, 'visibilityState', { configurable: true, get: () => 'visible' });
    Object.defineProperty(w.document, 'hidden', { configurable: true, get: () => false });
    Object.defineProperty(w.document, 'readyState', { configurable: true, get: () => 'complete' });
    if (!w.document.hasFocus || w.document.hasFocus() !== true) {
      w.document.hasFocus = native(function hasFocus() { return true; }, 'hasFocus');
    }
  } catch (_) {}
  w.matchMedia =
    w.matchMedia ||
    (q =>
      ({
        media: q,
        matches: false,
        onchange: null,
        addListener() {},
        removeListener() {},
        addEventListener() {},
        removeEventListener() {},
        dispatchEvent() {
          return false;
        },
      }));
  Object.defineProperty(w, 'visualViewport', {
    configurable: true,
    value: Object.freeze({
      offsetLeft: 0,
      offsetTop: 0,
      pageLeft: 0,
      pageTop: 0,
      width: 1920,
      height: 969,
      scale: 1,
      addEventListener() {},
      removeEventListener() {},
    }),
  });
  Object.defineProperty(w, 'screenLeft', { configurable: true, get: () => 0 });
  Object.defineProperty(w, 'screenTop', { configurable: true, get: () => 0 });
  Object.defineProperty(w, 'scrollX', { configurable: true, get: () => 0 });
  Object.defineProperty(w, 'scrollY', { configurable: true, get: () => 0 });
  Object.defineProperty(w, 'outerWidth', { get: () => 1920, configurable: true });
  Object.defineProperty(w, 'outerHeight', { get: () => 1040, configurable: true });
  Object.defineProperty(w, 'innerWidth', { get: () => 1920, configurable: true });
  Object.defineProperty(w, 'innerHeight', { get: () => 969, configurable: true });
  Object.defineProperty(w, 'devicePixelRatio', { get: () => 1, configurable: true });
  Object.defineProperty(w, 'screen', { value: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0 } }, configurable: true });
  const perfStart = Date.now();
  let _perfAccum = 0;
  try { if (!w.performance) w.performance = {}; } catch {}
  try {
    w.performance.now = function now() {
      _perfAccum += 0.01 + Math.random() * 0.04;
      return (Date.now() - perfStart) + _perfAccum;
    };
    native(w.performance.now, 'now');
  } catch {}
  try { Object.defineProperty(w.performance, 'timeOrigin', { get: () => perfStart, configurable: true }); } catch {}
  try { if (!w.performance.memory) Object.defineProperty(w.performance, 'memory', { get: () => ({ jsHeapSizeLimit: 4294705152, totalJSHeapSize: 35000000, usedJSHeapSize: 25000000 }), configurable: true }); } catch {}
  try { if (!w.performance.getEntriesByType) w.performance.getEntriesByType = () => []; } catch {};
  try { if (!w.performance.getEntriesByName) w.performance.getEntriesByName = () => []; } catch {};
  try {
    if (!w.performance.timing) {
      const ns = perfStart;
      Object.defineProperty(w.performance, 'timing', { configurable: true, get: () => ({
        navigationStart: ns, unloadEventStart: 0, unloadEventEnd: 0, redirectStart: 0, redirectEnd: 0,
        fetchStart: ns + 1, domainLookupStart: ns + 5, domainLookupEnd: ns + 15, connectStart: ns + 15,
        connectEnd: ns + 45, secureConnectionStart: ns + 20, requestStart: ns + 46, responseStart: ns + 120,
        responseEnd: ns + 300, domLoading: ns + 310, domInteractive: ns + 600, domContentLoadedEventStart: ns + 610,
        domContentLoadedEventEnd: ns + 620, domComplete: ns + 900, loadEventStart: ns + 905, loadEventEnd: ns + 910,
      })});
    }
  } catch {}
  try {
    if (!w.performance.navigation) Object.defineProperty(w.performance, 'navigation', { configurable: true, get: () => ({ type: 0, redirectCount: 0 }) });
  } catch {}
  let rafId = 0;
  w.requestAnimationFrame = w.requestAnimationFrame || ((cb) => { const id = ++rafId; setTimeout(() => cb(Date.now()), 16); return id; });
  w.cancelAnimationFrame = w.cancelAnimationFrame || (() => {});
  w.Notification = { permission: 'default', requestPermission: () => Promise.resolve('default') };
  w.speechSynthesis = w.speechSynthesis || { getVoices: () => [{ name: 'Microsoft David', lang: 'en-US', localService: true, default: true, voiceURI: 'Microsoft David - English (United States)' }], onvoiceschanged: null, speaking: false, pending: false, paused: false };
  if (!w.indexedDB) {
    const fakeDB = { open: () => { const req = { result: null, error: null, onsuccess: null, onerror: null, onupgradeneeded: null, readyState: 'done' }; setTimeout(() => { req.result = { close() {}, objectStoreNames: { length: 0, contains: () => false }, transaction: () => null }; req.onsuccess?.({ target: req }); }, 0); return req; }, deleteDatabase: () => { const r = { onsuccess: null }; setTimeout(() => r.onsuccess?.({ target: r }), 0); return r; }, cmp: () => 0 };
    try { Object.defineProperty(w, 'indexedDB', { configurable: true, get: () => fakeDB }); } catch {}
  }
  if (!w.caches) {
    try { Object.defineProperty(w, 'caches', { configurable: true, get: () => ({ open: () => Promise.resolve({ match: () => Promise.resolve(undefined), put: () => Promise.resolve(), delete: () => Promise.resolve(true), keys: () => Promise.resolve([]) }), has: () => Promise.resolve(false), keys: () => Promise.resolve([]), delete: () => Promise.resolve(true), match: () => Promise.resolve(undefined) }) }); } catch {}
  }
  if (!w.Worker) w.Worker = class { constructor() { this.onmessage = null; this.onerror = null; } postMessage() {} terminate() {} addEventListener() {} removeEventListener() {} };
  if (!w.SharedWorker) w.SharedWorker = class { constructor() { this.port = { start() {}, close() {}, postMessage() {}, onmessage: null, addEventListener() {}, removeEventListener() {} }; this.onerror = null; } };
  if (!w.MessageChannel) w.MessageChannel = class { constructor() { this.port1 = { postMessage() {}, close() {}, onmessage: null, addEventListener() {}, removeEventListener() {}, start() {} }; this.port2 = { postMessage() {}, close() {}, onmessage: null, addEventListener() {}, removeEventListener() {}, start() {} }; } };
  if (!w.BroadcastChannel) w.BroadcastChannel = class { constructor(n) { this.name = n; this.onmessage = null; } postMessage() {} close() {} addEventListener() {} removeEventListener() {} };
  if (!w.createImageBitmap) w.createImageBitmap = () => Promise.resolve({ width: 1, height: 1, close() {} });
  if (!w.structuredClone) w.structuredClone = (v) => JSON.parse(JSON.stringify(v));
  if (!w.document.elementsFromPoint) w.document.elementsFromPoint = () => [];
  try {
    const HEproto = w.HTMLElement?.prototype;
    if (HEproto) {
      for (const p of ['offsetWidth', 'offsetHeight', 'offsetLeft', 'offsetTop', 'clientWidth', 'clientHeight']) {
        const desc = Object.getOwnPropertyDescriptor(HEproto, p);
        if (!desc || desc.get === undefined) Object.defineProperty(HEproto, p, { configurable: true, get() { return p.includes('Width') ? 100 : p.includes('Height') ? 30 : 0; } });
      }
    }
  } catch {}
  w.chrome = w.chrome || {};
  Object.assign(w.chrome, {
    runtime: {
      OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' },
      OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' },
      PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
      PlatformOs: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' },
      RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' },
      /** Web sayfası bağlamı: kimlik doğrulama uzantı yokmuş gibi nötr */
      id: undefined,
      sendMessage: () => {},
      connect: () => ({
        disconnect() {},
        postMessage() {},
        onDisconnect: { addListener() {} },
        onMessage: { addListener() {} },
      }),
      ...(typeof w.chrome.runtime === 'object' && w.chrome.runtime ? w.chrome.runtime : {}),
    },
    loadTimes: function () { const t = Date.now() / 1000; return { firstPaintTime: 0, firstPaintAfterLoadTime: 0, requestTime: t - 1, startLoadTime: t - 1, commitLoadTime: t - 0.5, finishDocumentLoadTime: t - 0.4, finishLoadTime: t - 0.3, navigationType: 'Other', wasFetchedViaSpdy: true, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasAlternateProtocolAvailable: false, connectionInfo: 'h2' }; },
    csi: function () { return { startE: Date.now(), onloadT: Date.now(), pageT: 1234, tran: 15 }; },
    app: { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' } },
  });
  Object.defineProperty(w.chrome.runtime, 'lastError', { configurable: true, get: () => undefined });

  // ── Missing browser globals that BG checks for existence ──
  if (!w.Proxy) w.Proxy = Proxy;
  if (!w.WeakRef) w.WeakRef = WeakRef;
  if (!w.FinalizationRegistry) w.FinalizationRegistry = FinalizationRegistry;
  if (!w.SharedArrayBuffer) try { w.SharedArrayBuffer = SharedArrayBuffer; } catch { w.SharedArrayBuffer = class { constructor(n) { this.byteLength = n; } }; }
  if (!w.Atomics) try { w.Atomics = Atomics; } catch { w.Atomics = { wait: () => 'ok', notify: () => 0, isLockFree: () => true }; }
  if (!w.WebAssembly) try { w.WebAssembly = WebAssembly; } catch { w.WebAssembly = { compile: () => Promise.reject(), instantiate: () => Promise.reject(), validate: () => false, Module: class {}, Instance: class {}, Memory: class { constructor() { this.buffer = new ArrayBuffer(0); } }, Table: class {}, CompileError: class extends Error {}, LinkError: class extends Error {}, RuntimeError: class extends Error {} }; }
  if (!w.RTCPeerConnection) w.RTCPeerConnection = class { constructor() { this.localDescription = null; this.remoteDescription = null; this.connectionState = 'new'; } createDataChannel() { return {}; } createOffer() { return Promise.resolve({}); } createAnswer() { return Promise.resolve({}); } setLocalDescription() { return Promise.resolve(); } setRemoteDescription() { return Promise.resolve(); } close() {} addEventListener() {} removeEventListener() {} };
  if (!w.webkitRTCPeerConnection) { w.webkitRTCPeerConnection = w.RTCPeerConnection; if (BG_TRACE) console.log(`[shim] webkitRTCPeerConnection set? ${typeof w.webkitRTCPeerConnection}, readback: ${typeof w['webkitRTCPeerConnection']}`); }
  if (!w.webkitSpeechRecognition) { w.webkitSpeechRecognition = class { constructor() { this.continuous = false; this.interimResults = false; this.lang = ''; } start() {} stop() {} abort() {} addEventListener() {} removeEventListener() {} }; if (BG_TRACE) console.log(`[shim] webkitSpeechRecognition set? ${typeof w.webkitSpeechRecognition}, readback: ${typeof w['webkitSpeechRecognition']}`); }
  if (!w.ImageBitmap) w.ImageBitmap = class { constructor() { this.width = 0; this.height = 0; } close() {} };
  if (!w.OffscreenCanvas) w.OffscreenCanvas = class { constructor(ww, hh) { this.width = ww || 1; this.height = hh || 1; } getContext() { return null; } transferToImageBitmap() { return new w.ImageBitmap(); } };
  if (!w.ReportingObserver) w.ReportingObserver = class { constructor() {} observe() {} disconnect() {} takeRecords() { return []; } };
  if (!w.XPathEvaluator) w.XPathEvaluator = class { createExpression() { return { evaluate: () => ({ resultType: 0, numberValue: 0, stringValue: '', booleanValue: false, iterateNext: () => null, snapshotItem: () => null, snapshotLength: 0 }) }; } createNSResolver() { return null; } evaluate() { return { resultType: 0, iterateNext: () => null, snapshotLength: 0 }; } };
  if (!w.XPathResult) w.XPathResult = { ANY_TYPE: 0, NUMBER_TYPE: 1, STRING_TYPE: 2, BOOLEAN_TYPE: 3, UNORDERED_NODE_ITERATOR_TYPE: 4, ORDERED_NODE_ITERATOR_TYPE: 5, UNORDERED_NODE_SNAPSHOT_TYPE: 6, ORDERED_NODE_SNAPSHOT_TYPE: 7, ANY_UNORDERED_NODE_TYPE: 8, FIRST_ORDERED_NODE_TYPE: 9 };
  if (!w.requestIdleCallback) w.requestIdleCallback = (cb) => setTimeout(() => cb({ didTimeout: false, timeRemaining: () => 50 }), 0);
  if (!w.cancelIdleCallback) w.cancelIdleCallback = (id) => clearTimeout(id);
  if (!w.reportError) w.reportError = (e) => { console.error(e); };
  if (w.crossOriginIsolated === undefined) Object.defineProperty(w, 'crossOriginIsolated', { configurable: true, get: () => false });
  if (w.isSecureContext === undefined) Object.defineProperty(w, 'isSecureContext', { configurable: true, get: () => true });
  if (w.origin === undefined) Object.defineProperty(w, 'origin', { configurable: true, get: () => 'https://accounts.google.com' });
  if (!w.trustedTypes) w.trustedTypes = { createPolicy: (name) => ({ createHTML: (s) => s, createScript: (s) => s, createScriptURL: (s) => s }), isHTML: () => false, isScript: () => false, isScriptURL: () => false, emptyHTML: '', emptyScript: '', defaultPolicy: null };
  if (!w.scheduler) w.scheduler = { postTask: (cb) => Promise.resolve(cb()), yield: () => Promise.resolve() };
  if (!w.DocumentTimeline) w.DocumentTimeline = class { constructor() { this.currentTime = Date.now(); } };
  if (!w.Animation) w.Animation = class { constructor() { this.playState = 'idle'; this.currentTime = 0; } play() {} pause() {} cancel() {} finish() {} addEventListener() {} removeEventListener() {} };
  if (!w.KeyframeEffect) w.KeyframeEffect = class { constructor() {} };
  if (!w.CSSStyleSheet) w.CSSStyleSheet = class { constructor() { this.cssRules = []; } insertRule() { return 0; } deleteRule() {} };
  if (!w.StyleSheet) w.StyleSheet = class { constructor() { this.disabled = false; this.href = null; this.media = { length: 0 }; this.ownerNode = null; this.parentStyleSheet = null; this.title = null; this.type = 'text/css'; } };
  if (!w.MediaQueryList) w.MediaQueryList = class { constructor(q) { this.media = q || ''; this.matches = false; } addEventListener() {} removeEventListener() {} addListener() {} removeListener() {} };
  if (!w.CanvasRenderingContext2D) w.CanvasRenderingContext2D = class {};
  if (!w.WebGLRenderingContext) w.WebGLRenderingContext = class {};
  if (!w.WebGL2RenderingContext) w.WebGL2RenderingContext = class {};
  if (!w.AudioWorklet) w.AudioWorklet = class { addModule() { return Promise.resolve(); } };
  if (!w.BaseAudioContext) w.BaseAudioContext = w.AudioContext || class {};
  if (!w.GPU) w.GPU = class { async requestAdapter() { return null; } };
  if (!w.GPUAdapter) w.GPUAdapter = class {};
  if (!w.NavigatorUAData) w.NavigatorUAData = class {};
  if (!w.MediaStream) w.MediaStream = class { constructor() { this.id = 'fake'; this.active = false; } getTracks() { return []; } getAudioTracks() { return []; } getVideoTracks() { return []; } addEventListener() {} removeEventListener() {} };

  harden(w);

  function maskProps(obj) {
    if (!obj || typeof obj !== 'object') return;
    for (const k of Object.getOwnPropertyNames(obj)) {
      try {
        const d = Object.getOwnPropertyDescriptor(obj, k);
        if (d && typeof d.value === 'function') native(d.value, k);
        if (d && typeof d.get === 'function') native(d.get, 'get ' + k);
      } catch {}
    }
  }
  maskProps(w.navigator);
  maskProps(w.chrome);
  maskProps(w.chrome?.runtime);
  if (w.matchMedia) native(w.matchMedia, 'matchMedia');
  if (w.getComputedStyle) native(w.getComputedStyle, 'getComputedStyle');
  if (w.requestAnimationFrame) native(w.requestAnimationFrame, 'requestAnimationFrame');
  if (w.cancelAnimationFrame) native(w.cancelAnimationFrame, 'cancelAnimationFrame');
}

function applyBabloPayload(win, payload) {
  if (!payload) return;
  try {
    win.eval(payload);
  } catch (e) {
    console.log('[bablo] payload exec error:', e.message);
  }
}

const BG_TRACE = process.env.GLIF_BG_TRACE === '1';
function makeBG(vmCode, bc, contentBinding) {
  // ── Global Error.prepareStackTrace: sanitize ALL V8 stack traces during BG execution ──
  const _origPST = Error.prepareStackTrace;
  const _fakeUrl = 'https://accounts.google.com/v3/signin/identifier';
  Error.prepareStackTrace = function(err, callSites) {
    const sanitized = callSites.map(cs => new Proxy(cs, {
      get(t, prop) {
        if (prop === 'getFileName' || prop === 'getScriptNameOrSourceURL')
          return () => _fakeUrl;
        if (prop === 'getEvalOrigin') return () => _fakeUrl;
        const v = Reflect.get(t, prop);
        return typeof v === 'function' ? v.bind(t) : v;
      }
    }));
    if (_origPST) return _origPST(err, sanitized);
    return err.toString() + '\n' + sanitized.map(cs =>
      `    at ${cs.getFunctionName() || '<anonymous>'} (${_fakeUrl}:${cs.getLineNumber()}:${cs.getColumnNumber()})`
    ).join('\n');
  };

  const win = new Window({url:'https://accounts.google.com/v3/signin/identifier',width:1920,height:969});
  shimWindow(win);
  applyBabloPayload(win, _babloPayload);

  // ─── BG VM tracing: log every toString call, missing prop, and type check ───
  if (BG_TRACE) {
    const _bgLog = [];
    const _fnToStr = win.Function.prototype.toString;
    const _origFnToStr = Function.prototype.toString;
    win.Function.prototype.toString = function () {
      const result = _fnToStr.call(this);
      const isNative = result.includes('[native code]');
      const name = this.name || '(anon)';
      if (!isNative) _bgLog.push(`[FN.toString] NOT NATIVE: ${name} → ${result.substring(0, 120)}`);
      return result;
    };
    _nativeMasked.add(win.Function.prototype.toString);

    // Track Object.prototype.toString calls (type checks like [object X])
    const _objToStr = Object.prototype.toString;
    // Hook specific navigator/document calls BG commonly checks
    const origGetElementById = win.document.getElementById.bind(win.document);
    win.document.getElementById = function(id) { _bgLog.push(`[doc.getElementById] "${id}"`); return origGetElementById(id); };
    _nativeMasked.add(win.document.getElementById);
    const origQSA = win.document.querySelectorAll.bind(win.document);
    win.document.querySelectorAll = function(sel) { _bgLog.push(`[doc.querySelectorAll] "${sel}"`); return origQSA(sel); };
    _nativeMasked.add(win.document.querySelectorAll);
    const origCE = win.document.createElement.bind(win.document);
    win.document._origCE = origCE;
    win.document.createElement = function(tag, opts) { _bgLog.push(`[doc.createElement] "${tag}"`); return origCE(tag, opts); };
    _nativeMasked.add(win.document.createElement);

    // Non-invasive: hook win.eval to see if BG evals detection code
    const origEval = win.eval;
    win.eval = function(code) {
      if (typeof code === 'string' && code.length < 500 && /toString|native|prototype|constructor|getOwnProperty/i.test(code))
        _bgLog.push(`[eval] ${code.substring(0, 200)}`);
      return origEval.call(this, code);
    };

    // Track window property reads that return undefined
    const winMissing = new Set();
    const origGet = Object.getOwnPropertyDescriptor;
    const importantWinProps = ['chrome','Notification','speechSynthesis','webkitSpeechRecognition',
      'RTCPeerConnection','webkitRTCPeerConnection','MediaStream','ImageBitmap',
      'OffscreenCanvas','WebSocket','fetch','XMLHttpRequest','MutationObserver',
      'IntersectionObserver','ResizeObserver','PerformanceObserver','ReportingObserver',
      'Intl','Reflect','Proxy','Symbol','WeakRef','FinalizationRegistry',
      'SharedArrayBuffer','Atomics','WebAssembly','TextEncoder','TextDecoder',
      'AbortController','AbortSignal','URL','URLSearchParams','FormData','Headers',
      'Request','Response','ReadableStream','WritableStream','TransformStream',
      'Blob','File','FileReader','FileList','DOMParser','XMLSerializer',
      'XPathEvaluator','XPathResult','NodeFilter','TreeWalker','Range',
      'Selection','getSelection','requestIdleCallback','cancelIdleCallback',
      'queueMicrotask','structuredClone','reportError','crossOriginIsolated',
      'isSecureContext','origin','trustedTypes','scheduler',
      'DocumentTimeline','Animation','KeyframeEffect',
      'CSSStyleSheet','StyleSheet','MediaQueryList',
      'CanvasRenderingContext2D','WebGLRenderingContext','WebGL2RenderingContext',
      'AudioContext','OfflineAudioContext','AudioWorklet','BaseAudioContext',
      'GPU','GPUAdapter','NavigatorUAData'];
    for (const p of importantWinProps) {
      if (win[p] === undefined && !winMissing.has(p)) {
        winMissing.add(p);
        _bgLog.push(`[win.${p}] MISSING (undefined)`);
      }
    }

    // After BG runs, dump the trace
    const _origSnapshot = null;
    win.__bgTraceLog = _bgLog;
    // Schedule dump after BG finishes
    setTimeout(() => {
      if (_bgLog.length) {
        console.log(`\n[BG-TRACE] ${_bgLog.length} entries:`);
        const toStrCalls = _bgLog.filter(l => l.startsWith('[FN.toString]'));
        const missing = _bgLog.filter(l => l.includes('MISSING'));
        const navReads = _bgLog.filter(l => l.startsWith('[nav.'));
        const docMissing = _bgLog.filter(l => l.startsWith('[doc.') && l.includes('undefined'));
        if (toStrCalls.length) { console.log(`  --- toString NOT NATIVE (${toStrCalls.length}) ---`); for (const l of toStrCalls) console.log('  ' + l); }
        if (missing.length) { console.log(`  --- MISSING window props (${missing.length}) ---`); for (const l of missing) console.log('  ' + l); }
        if (docMissing.length) { console.log(`  --- MISSING document props (${docMissing.length}) ---`); for (const l of docMissing) console.log('  ' + l); }
        if (navReads.length) { console.log(`  --- navigator reads (${navReads.length}) ---`); for (const l of navReads.slice(0, 60)) console.log('  ' + l); if (navReads.length > 60) console.log(`  ... (${navReads.length - 60} more)`); }
        console.log('[BG-TRACE] end\n');
      }
    }, 28000);
  }
  // ─── end BG tracing ───

  // Intercept iframe creation to apply shims to iframe contentWindow
  const origCreateElement = (win.document._origCE || win.document.createElement).bind(win.document);
  const _prevCE = win.document.createElement;
  win.document.createElement = function(tag, opts) {
    const el = origCreateElement(tag, opts);
    if (BG_TRACE && win.__bgTraceLog) win.__bgTraceLog.push(`[doc.createElement] "${tag}"`);
    if (tag.toLowerCase() === 'iframe') {
      let patched = false;
      const origCW = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'contentWindow');
      if (origCW) {
        Object.defineProperty(el, 'contentWindow', {
          get() {
            const cw = origCW.get.call(this);
            if (cw && !patched) {
              patched = true;
              try { shimWindow(cw); applyBabloPayload(cw, _babloPayload); } catch {}
              // BG probes contentWindow.location.href.match(/^h/) — must return https URL
              try {
                const iframeSrc = el.src || 'https://accounts.google.com/_/bscframe';
                Object.defineProperty(cw, 'location', {
                  value: { href: iframeSrc, protocol: 'https:', hostname: 'accounts.google.com', pathname: '/', toString: () => iframeSrc },
                  configurable: true,
                });
              } catch {}
            }
            return cw;
          },
          configurable: true,
        });
      }
      // BG checks sandbox.supports() — provide stub
      try {
        Object.defineProperty(el, 'sandbox', {
          value: { add() {}, remove() {}, contains() { return true; }, supports() { return true; }, toString() { return ''; }, length: 0 },
          configurable: true, writable: true,
        });
      } catch {}
    }
    return el;
  };

  // Patch VM code: inject integCheckBypass into every new VM instance
  // The `tI` function initializes VM state — inject the flag there
  const patchedVmCode = vmCode.replace(
    /v\.ns=!\(v\.W=\[\],1\)/,
    'v.ns=!(v.W=[],1),v.integCheckBypass={}'
  );
  win.eval(patchedVmCode || vmCode);

  // ── Synthetic behavioral events: BG's Welford stats need non-zero variance ──
  function injectBehavioralEvents() {
    const doc = win.document;
    const opts = { bubbles: true, cancelable: true };
    let baseX = 400 + Math.random() * 200, baseY = 300 + Math.random() * 100;
    const mouseOpts = (x, y) => ({ ...opts, clientX: x, clientY: y, screenX: x, screenY: y + 71, pageX: x, pageY: y, button: 0, buttons: 0 });
    for (let i = 0; i < 12 + (Math.random() * 8 | 0); i++) {
      baseX += (Math.random() - 0.3) * 40;
      baseY += (Math.random() - 0.5) * 20;
      try { doc.dispatchEvent(new win.MouseEvent('mousemove', mouseOpts(baseX | 0, baseY | 0))); } catch {}
    }
    try { doc.dispatchEvent(new win.MouseEvent('mousedown', mouseOpts(baseX | 0, baseY | 0))); } catch {}
    try { doc.dispatchEvent(new win.MouseEvent('mouseup', mouseOpts(baseX | 0, baseY | 0))); } catch {}
    try { doc.dispatchEvent(new win.MouseEvent('click', mouseOpts(baseX | 0, baseY | 0))); } catch {}
    const keys = ['c', 'a', 'g', 'r', 'u'];
    for (const k of keys) {
      const ko = { ...opts, key: k, code: `Key${k.toUpperCase()}`, keyCode: k.charCodeAt(0), which: k.charCodeAt(0) };
      try { doc.dispatchEvent(new win.KeyboardEvent('keydown', ko)); } catch {}
      try { doc.dispatchEvent(new win.KeyboardEvent('keyup', ko)); } catch {}
    }
    try { doc.dispatchEvent(new win.Event('scroll', opts)); } catch {}
    try { win.dispatchEvent(new win.Event('scroll', opts)); } catch {}
  }
  const bind = contentBinding !== undefined ? contentBinding : glifContentBinding();
  const uiAnchor = bgUserInteractionStub(win);
  return BotGuardClient.create({
      globalObj: win,
      globalName: 'botguard',
      program: bc,
      ...(uiAnchor ? { userInteractionElement: uiAnchor } : {}),
    })
    .then(bg => {
      try { injectBehavioralEvents(); } catch (e) { if (BG_TRACE) console.log('[bg] behavioral inject error:', e.message); }
      return new Promise(resolve => setTimeout(() => resolve(bg), 300 + Math.random() * 200));
    })
    .then(bg => bg.snapshot({ contentBinding: bind }, 25000))
    .then(tok => {
      if (BG_TRACE && win.__bgTraceLog?.length) {
        const _bgLog = win.__bgTraceLog;
        console.log(`\n[BG-TRACE] ${_bgLog.length} entries:`);
        const toStrCalls = _bgLog.filter(l => l.startsWith('[FN.toString]'));
        const missing = _bgLog.filter(l => l.includes('MISSING'));
        const docMissing = _bgLog.filter(l => l.startsWith('[doc.') && l.includes('null'));
        if (toStrCalls.length) { console.log(`  --- toString NOT NATIVE (${toStrCalls.length}) ---`); for (const l of toStrCalls) console.log('  ' + l); }
        if (missing.length) { console.log(`  --- MISSING window props (${missing.length}) ---`); for (const l of missing) console.log('  ' + l); }
        const gopdCalls = _bgLog.filter(l => l.startsWith('[GOPD]'));
        if (gopdCalls.length) { console.log(`  --- getOwnPropertyDescriptor (${gopdCalls.length}) ---`); for (const l of gopdCalls.slice(0,50)) console.log('  ' + l); if (gopdCalls.length > 50) console.log(`  ... (${gopdCalls.length-50} more)`); }
        const gopnCalls = _bgLog.filter(l => l.startsWith('[GOPN]'));
        if (gopnCalls.length) { console.log(`  --- getOwnPropertyNames (${gopnCalls.length}) ---`); for (const l of gopnCalls) console.log('  ' + l); }
        const objToStr = _bgLog.filter(l => l.startsWith('[Object.toString]'));
        if (objToStr.length) { console.log(`  --- Object.toString type checks (${objToStr.length}) ---`); for (const l of objToStr) console.log('  ' + l); }
        const evalCalls = _bgLog.filter(l => l.startsWith('[eval]'));
        if (evalCalls.length) { console.log(`  --- eval calls (${evalCalls.length}) ---`); for (const l of evalCalls) console.log('  ' + l); }
        const domCalls = _bgLog.filter(l => l.startsWith('[doc.'));
        if (domCalls.length) { console.log(`  --- DOM calls (${domCalls.length}) ---`); for (const l of domCalls.slice(0,40)) console.log('  ' + l); }
      }
      return tok;
    })
    .finally(() => { Error.prepareStackTrace = _origPST; win.happyDOM.close(); });
}

// ═══════════════════════════════════════════════════════════════════
// BG Token Generator Main
// Usage: node glogin_final_6.mjs [--binding '{"Ko":{"replayKey":"x"}}'] [--url <page_url>]
// Output: raw BG token to stdout
// ═══════════════════════════════════════════════════════════════════

const _args = process.argv.slice(2);
function _arg(name) {
  const i = _args.indexOf('--' + name);
  if (i < 0 || i + 1 >= _args.length) return null;
  let v = _args[i + 1];
  if (v.startsWith("'") && v.endsWith("'")) v = v.slice(1, -1);
  return v;
}

const PAGE_URL = _arg('url') || 'https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&service=mail&flowName=GlifWebSignIn&flowEntry=ServiceLogin';
let BINDING = { Ko: { replayKey: 'default' } };
if (_arg('binding')) {
  try { BINDING = JSON.parse(_arg('binding')); }
  catch { process.stderr.write('Invalid --binding JSON\n'); process.exit(1); }
}

// Fetch BabloSoft fingerprint
await fetchBabloFingerprint();

// Fetch page and extract BG challenge
const _pageResp = await fetch(PAGE_URL, { headers: { 'User-Agent': glifActiveUAChrome() }, redirect: 'follow' });
const _html = await _pageResp.text();

function _parseDS(html, key) {
  const m = html.indexOf(`key: '${key}'`);
  if (m < 0) return null;
  const dp = html.indexOf('data:', m);
  const as = html.indexOf('[', dp);
  let d = 0, p = as, s = false, e = false;
  for (; p < html.length; p++) {
    const c = html[p];
    if (e) { e = false; continue; }
    if (c === '\\') { e = true; continue; }
    if (c === '"') { s = !s; continue; }
    if (s) continue;
    if (c === '[') d++;
    if (c === ']') { d--; if (d === 0) break; }
  }
  return JSON.parse(html.substring(as, p + 1).replace(/\\u003d/g, '=').replace(/\\u003c/g, '<').replace(/\\u003e/g, '>'));
}

let _ds = _parseDS(_html, 'ds:3');
let _vmCode = _ds?.[4]?.[1]?.[5] || '';
if (!_vmCode) { _ds = _parseDS(_html, 'ds:2'); _vmCode = _ds?.[4]?.[1]?.[5] || ''; }
if (!_vmCode) { process.stderr.write('No VM code found\n'); process.exit(1); }
const _bcm = JSON.stringify(_ds).match(/"([A-Za-z0-9+\/=]{10000,})"/);
if (!_bcm) { process.stderr.write('No bytecode found\n'); process.exit(1); }

const _token = await makeBG(_vmCode, _bcm[1], BINDING);

if (!_token || !_token.startsWith('!')) {
  process.stderr.write('BG token generation failed\n');
  process.exit(1);
}

process.stdout.write(_token);
