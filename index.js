/**
 * earnity-orders — Cloudflare Worker (All-in-one bundle)
 * Order lifecycle, pricing locks, delivery codes, contact privacy, outbox & receipts.
 */

const JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const ALLOWED_HOST = 'earnityug.com';
const PAYMENT_FEE_BPS = 175;
const ORDER_PAY_WINDOW_SECONDS = 1800;
const CODE_MAX_ATTEMPTS = 5;
const CODE_MAX_RESENDS = 3;
const CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

const enc = new TextEncoder();
const dec = new TextDecoder();

let jwksMem = { keys: null, expires: 0 };
const keyMem = new Map();
let hmacKeyCache = { salt: null, key: null };
let aesKeyCache = { secret: null, key: null };
let lastForced = 0;

class HttpError extends Error {
  constructor(status, code, extra) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function json(data, status, cors, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...cors,
      ...extraHeaders,
    },
  });
}

function corsHeaders(origin) {
  if (!origin) return { Vary: 'Origin' };
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Visitor-Id',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return (
      u.protocol === 'https:' &&
      (u.hostname === ALLOWED_HOST || u.hostname.endsWith('.' + ALLOWED_HOST))
    );
  } catch {
    return false;
  }
}

function assertEnv(env, names) {
  for (const name of names) {
    if (!env[name]) {
      console.error('missing_env', { name });
      throw new HttpError(500, 'server_misconfigured');
    }
  }
}

function generateId(prefix) {
  const rand = crypto.getRandomValues(new Uint8Array(8));
  return (
    prefix +
    Date.now().toString(36) +
    Array.from(rand)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  );
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function b64urlDecode(input) {
  let s = input.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function timingSafeEqual(a, b) {
  if (typeof a === 'string') a = enc.encode(a);
  if (typeof b === 'string') b = enc.encode(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function readJson(request) {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (ct !== 'application/json' && !ct.startsWith('application/json;')) {
    throw new HttpError(415, 'unsupported_media_type');
  }
  const len = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(len) && len > 4096) {
    throw new HttpError(413, 'payload_too_large');
  }
  const text = await request.text();
  if (enc.encode(text).length > 4096) {
    throw new HttpError(413, 'payload_too_large');
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'invalid_json');
  }
  return data;
}

async function hmacHex(env, message) {
  let key = hmacKeyCache.key;
  if (!key || hmacKeyCache.salt !== env.HASH_SALT) {
    key = await crypto.subtle.importKey(
      'raw',
      enc.encode(env.HASH_SALT),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    hmacKeyCache = { salt: env.HASH_SALT, key };
  }
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bufToHex(sig);
}

async function getAesKey(env) {
  let key = aesKeyCache.key;
  if (!key || aesKeyCache.secret !== env.CODE_ENC_KEY) {
    const raw = await crypto.subtle.digest('SHA-256', enc.encode(env.CODE_ENC_KEY));
    key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    aesKeyCache = { secret: env.CODE_ENC_KEY, key };
  }
  return key;
}

async function encryptCode(env, plainCode) {
  const key = await getAesKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plainCode));
  return {
    cipher: bufToHex(cipherBuf),
    iv: bufToHex(iv),
  };
}

async function decryptCode(env, cipherHex, ivHex) {
  const key = await getAesKey(env);
  const cipherBytes = new Uint8Array(cipherHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
  const ivBytes = new Uint8Array(ivHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, cipherBytes);
  return dec.decode(plainBuf);
}

function generateDeliveryCode() {
  const rand = crypto.getRandomValues(new Uint8Array(6));
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += CODE_CHARS[rand[i] % CODE_CHARS.length];
  }
  return code;
}

async function getJwks(env, force) {
  const now = Date.now();
  if (!force && jwksMem.keys && jwksMem.expires > now) return jwksMem.keys;
  const res = await fetch(
    JWKS_URL,
    force
      ? { cache: 'no-store', cf: { cacheTtl: 0, cacheEverything: false } }
      : { cf: { cacheTtl: 3600, cacheEverything: true } }
  );
  if (!res.ok) throw new Error('jwks_fetch_failed');
  const data = await res.json();
  if (!Array.isArray(data.keys)) throw new Error('jwks_invalid');
  jwksMem = { keys: data.keys, expires: now + 3600000 };
  return data.keys;
}

async function importJwk(jwk) {
  const cached = keyMem.get(jwk.kid);
  if (cached && cached.expires > Date.now()) return cached.key;
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  keyMem.set(jwk.kid, { key, expires: Date.now() + 3600000 });
  return key;
}

async function getKey(kid, env) {
  let keys = await getJwks(env, false);
  let jwk = keys.find((k) => k.kid === kid);
  if (!jwk) {
    const now = Date.now();
    if (now - lastForced >= 60000) {
      lastForced = now;
      keys = await getJwks(env, true);
      jwk = keys.find((k) => k.kid === kid);
    }
  }
  if (!jwk) throw new Error('key_not_found');
  return importJwk(jwk);
}

async function verifyFirebaseToken(token, env, now) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed');
  const [headerPart, payloadPart, sigPart] = parts;
  const header = JSON.parse(dec.decode(b64urlDecode(headerPart)));
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('alg');
  const payload = JSON.parse(dec.decode(b64urlDecode(payloadPart)));
  const key = await getKey(header.kid, env);
  const data = enc.encode(`${headerPart}.${payloadPart}`);
  const sig = b64urlDecode(sigPart);
  const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, data);
  if (!valid) throw new Error('signature');
  if (typeof payload.exp !== 'number' || payload.exp <= now) throw new Error('exp');
  if (typeof payload.iat !== 'number' || payload.iat > now + 60) throw new Error('iat');
  if (payload.aud !== env.FIREBASE_PROJECT_ID) throw new Error('aud');
  if (payload.iss !== `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`) throw new Error('iss');
  return payload;
}

async function requireAuth(request, env, now) {
  const auth = request.headers.get('Authorization');
  if (!auth) throw new HttpError(401, 'unauthorized');
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new HttpError(401, 'unauthorized');
  let payload;
  try {
    payload = await verifyFirebaseToken(match[1], env, now);
  } catch {
    throw new HttpError(401, 'invalid_token');
  }
  const user = await env.DB.prepare(
    'SELECT id, email, display_name, account_type, is_admin, status FROM users WHERE firebase_uid = ? LIMIT 1'
  )
    .bind(payload.sub)
    .first();
  if (!user) throw new HttpError(404, 'not_registered');
  if (user.status === 'blocked') throw new HttpError(403, 'account_blocked');
  return { user, payload };
}

async function requireInternal(request, env) {
  if (request.headers.get('Origin')) throw new HttpError(403, 'forbidden');
  assertEnv(env, ['DB', 'INTERNAL_KEY']);
  const provided = request.headers.get('X-Internal-Key') || '';
  if (!timingSafeEqual(provided, env.INTERNAL_KEY)) {
    throw new HttpError(401, 'unauthorized');
  }
}

function assertId(value, code) {
  if (typeof value !== 'string' || value.length === 0 || value.length >= 128) {
    throw new HttpError(400, code || 'invalid_id');
  }
  return value;
}

function formatUgx(amount) {
  return Number(amount || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function formatDate(unixSeconds) {
  const d = new Date(Number(unixSeconds) * 1000);
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  return `${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function stripInternal(order, hideShares) {
  const out = { ...order };
  for (const k of ['code_hash', 'code_cipher', 'code_iv', 'payment_id']) delete out[k];
  if (hideShares) {
    for (const k of Object.keys(out)) {
      if (k.startsWith('product_referee_') || k.startsWith('business_referrer_') ||
          ['discount_id', 'earnity_ugx', 'earnity_bps', 'seller_reserve_bps', 'seller_user_id'].includes(k)) {
        delete out[k];
      }
    }
  }
  return out;
}

async function callService(serviceBinding, path, body, env) {
  try {
    const res = await serviceBinding.fetch(`https://internal${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': env.INTERNAL_KEY,
      },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new HttpError(res.status, data.error || 'service_error', data);
    }
    return data;
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(503, 'upstream_unavailable');
  }
}

/* ------------------------------------------------------------------ */
/* Endpoint Handlers                                                  */
/* ------------------------------------------------------------------ */

async function handleHealth(env, now, cors) {
  return json({ ok: true, service: 'earnity-orders', time: now }, 200, cors);
}

async function handleCreateOrder(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'INTERNAL_KEY']);
  const { user } = await requireAuth(request, env, now);

  const phoneRes = await callService(env.VERIFY, '/internal/phone-status', { user_id: user.id }, env);
  if (!phoneRes.phone_verified) {
    throw new HttpError(403, 'phone_not_verified');
  }

  const hourAgo = now - 3600;
  const countRow = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM orders WHERE buyer_user_id = ? AND created_at >= ?'
  ).bind(user.id, hourAgo).first();
  if (Number(countRow?.n || 0) >= 10) {
    throw new HttpError(429, 'rate_limit_exceeded');
  }

  const body = await readJson(request);
  const productId = assertId(body.product_id, 'invalid_product_id');
  const discountId = body.discount_id != null ? String(body.discount_id) : null;
  const visitorId = body.visitor_id != null ? String(body.visitor_id) : null;

  const productRow = await env.DB.prepare(
    `SELECT p.*, b.owner_user_id, b.name AS business_name, b.approval_status
     FROM products p JOIN businesses b ON b.id = p.business_id
     WHERE p.id = ? AND p.status = 'active' AND b.approval_status = 'approved' LIMIT 1`
  ).bind(productId).first();

  if (!productRow) throw new HttpError(404, 'product_not_found');
  if (productRow.owner_user_id === user.id) {
    throw new HttpError(400, 'own_product');
  }

  const quote = await callService(env.CATALOG, '/internal/checkout-quote', { product_id: productId }, env);
  const settingsRow = await env.DB.prepare('SELECT value_int FROM platform_settings WHERE key = ?').bind('deposit_cap_bps').first();
  const depositCapBps = Number(settingsRow?.value_int || 5000);

  const attr = await callService(env.REFERRALS, '/internal/attribution', {
    product_id: productId,
    buyer_user_id: user.id,
    visitor_id: visitorId,
    discount_id: discountId,
  }, env);

  const P = Number(attr.effective_price_ugx);
  const D = attr.discount ? Number(attr.discount.discount_ugx) : 0;
  const buyerPrice = P - D;

  let netPr = 0;
  let payablePr = 0;
  let surchargePr = 0;
  let prUserId = null;
  let prCommBps = Number(productRow.commission_bps || 0);
  let prDiscBps = 0;
  let prGross = 0;
  let prSource = null;

  if (attr.product_referee) {
    const arPr = attr.product_referee;
    prUserId = arPr.user_id;
    netPr = Number(arPr.net_ugx);
    payablePr = Number(arPr.payable_ugx);
    surchargePr = Number(arPr.earnity_surcharge_ugx);
    prCommBps = Number(arPr.commission_bps);
    prDiscBps = Number(arPr.discount_bps);
    prGross = Number(arPr.gross_ugx);
    prSource = arPr.source;
  }

  let grossBr = Number(quote.shares.business_referrer_ugx || 0);
  let payableBr = 0;
  let surchargeBr = 0;
  let brUserId = quote.business_referrer_user_id;
  let brBps = Number(quote.business_referrer_bps || 0);

  if (attr.business_referrer) {
    const arBr = attr.business_referrer;
    if (Number(arBr.gross_ugx) !== grossBr) {
      throw new HttpError(500, 'quote_mismatch');
    }
    payableBr = Number(arBr.payable_ugx);
    surchargeBr = Number(arBr.earnity_surcharge_ugx);
  }

  const sellerReserve = Number(quote.shares.seller_reserve_ugx || 0);
  const earnityBase = Number(quote.shares.earnity_ugx || 0);
  const earnityTotal = earnityBase + surchargePr + surchargeBr;

  const deposit = Number(quote.total_deposit_ugx) + netPr;

  if (deposit !== payablePr + payableBr + sellerReserve + earnityTotal) {
    throw new HttpError(500, 'split_mismatch');
  }

  if (deposit > Math.floor((P * depositCapBps) / 10000)) {
    throw new HttpError(400, 'deposit_cap_exceeded');
  }

  const paymentFee = Math.ceil((deposit * PAYMENT_FEE_BPS) / 10000);
  const totalCharged = deposit + paymentFee;
  const balanceDue = buyerPrice - deposit;

  const orderId = generateId('ord_');
  const dateStr = new Date(now * 1000).toISOString().slice(0, 10).replace(/-/g, '');
  const randDigits = Math.floor(10000 + Math.random() * 90000);
  const orderNumber = `EU-${dateStr}-${randDigits}`;
  const expiresAt = now + ORDER_PAY_WINDOW_SECONDS;

  const rateEarnityBps = Number(quote.earnity_bps || 0);
  const rateReserveBps = Number(quote.seller_reserve_bps || 0);

  let inserted = false;
  let finalOrderNumber = orderNumber;

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      await env.DB.prepare(
        `INSERT INTO orders (
           id, order_number, buyer_user_id, seller_user_id, business_id, product_id, status,
           product_name, business_name, delivery_text, delivery_days,
           price_ugx, discount_ugx, buyer_price_ugx, deposit_ugx, payment_fee_ugx, total_charged_ugx, balance_due_ugx,
           product_referee_user_id, product_referee_commission_bps, product_referee_discount_bps,
           product_referee_gross_ugx, product_referee_net_ugx, product_referee_payable_ugx, product_referee_surcharge_ugx,
           product_referee_source, discount_id,
           business_referrer_user_id, business_referrer_bps, business_referrer_gross_ugx,
           business_referrer_payable_ugx, business_referrer_surcharge_ugx,
           seller_reserve_ugx, earnity_ugx,
           earnity_bps, seller_reserve_bps, fee_bps,
           created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'awaiting_payment', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        orderId, finalOrderNumber, user.id, productRow.owner_user_id, productRow.business_id, productRow.id,
        productRow.name, productRow.business_name, productRow.delivery_text, Number(productRow.delivery_days || 3),
        P, D, buyerPrice, deposit, paymentFee, totalCharged, balanceDue,
        prUserId, prCommBps, prDiscBps, prGross, netPr, payablePr, surchargePr, prSource, discountId,
        brUserId, brBps, grossBr, payableBr, surchargeBr,
        sellerReserve, earnityTotal,
        rateEarnityBps, rateReserveBps, PAYMENT_FEE_BPS,
        now, expiresAt
      ).run();
      inserted = true;
      break;
    } catch (err) {
      if (String(err?.message || '').includes('UNIQUE')) {
        if (!String(err?.message || '').includes('order_number')) {
          throw new HttpError(409, 'order_already_pending');
        }
        const altRand = Math.floor(10000 + Math.random() * 90000);
        finalOrderNumber = `EU-${dateStr}-${altRand}`;
        continue;
      }
      throw err;
    }
  }

  if (!inserted) {
    throw new HttpError(500, 'order_number_collision');
  }

  await env.DB.prepare(
    'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(generateId('ev_'), orderId, 'created', user.id, 'buyer', JSON.stringify({ total_charged: totalCharged }), now).run();

  return json({
    order: {
      id: orderId,
      order_number: finalOrderNumber,
      status: 'awaiting_payment',
      product_name: productRow.name,
      business_name: productRow.business_name,
      buyer_price_ugx: buyerPrice,
      deposit_ugx: deposit,
      payment_fee_ugx: paymentFee,
      total_charged_ugx: totalCharged,
      balance_due_ugx: balanceDue,
      expires_at: expiresAt,
      created_at: now,
    },
    notice: 'The seller will see your name, phone and email after you pay.',
    footnote: 'Charged for processing mobile money and card payments.',
  }, 201, cors);
}

async function handleGetOrdersBuyer(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  const url = new URL(request.url);
  const cursor = Number(url.searchParams.get('cursor') || now + 99999999);

  const rows = await env.DB.prepare(
    `SELECT id, order_number, status, product_name, business_name, total_charged_ugx, balance_due_ugx, created_at, expires_at
     FROM orders WHERE buyer_user_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT 20`
  ).bind(user.id, cursor).all();

  const results = rows.results || [];
  const nextCursor = results.length === 20 ? results[results.length - 1].created_at : null;

  return json({ orders: results, next_cursor: nextCursor }, 200, cors);
}

async function handleGetOrderDetailBuyer(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  assertId(id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? AND buyer_user_id = ? LIMIT 1')
    .bind(id, user.id).first();
  if (!order) throw new HttpError(404, 'order_not_found');

  let plainCode = null;
  if ((order.status === 'paid' || order.status === 'under_review') && order.code_cipher && order.code_iv) {
    try {
      plainCode = await decryptCode(env, order.code_cipher, order.code_iv);
    } catch {}
  }

  return json({
    order: {
      ...stripInternal(order, true),
      delivery_code: plainCode,
    },
  }, 200, cors);
}

async function handleCancelOrder(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  assertId(id, 'invalid_order_id');

  const res = await env.DB.prepare(
    `UPDATE orders SET status = 'cancelled' WHERE id = ? AND buyer_user_id = ? AND status = 'awaiting_payment'`
  ).bind(id, user.id).run();

  if ((res?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(404, 'order_not_found_or_not_cancellable');
  }

  await env.DB.prepare(
    'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(generateId('ev_'), id, 'cancelled', user.id, 'buyer', '{}', now).run();

  return json({ cancelled: true }, 200, cors);
}

async function handleResendCode(request, env, id, now, cors) {
  assertEnv(env, ['DB', 'CODE_ENC_KEY', 'HASH_SALT']);
  const { user } = await requireAuth(request, env, now);
  assertId(id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? AND buyer_user_id = ? LIMIT 1')
    .bind(id, user.id).first();
  if (!order) throw new HttpError(404, 'order_not_found');
  if (order.status !== 'paid' && order.status !== 'under_review') {
    throw new HttpError(400, 'invalid_order_status');
  }
  if (Number(order.code_resends || 0) >= CODE_MAX_RESENDS) {
    throw new HttpError(429, 'max_resends_exceeded');
  }

  const newCode = generateDeliveryCode();
  const nextGen = Number(order.code_generation || 1) + 1;
  const nextResends = Number(order.code_resends || 0) + 1;
  const codeHash = await hmacHex(env, `code:${id}:${nextGen}:${newCode}`);
  const encRes = await encryptCode(env, newCode);

  const res = await env.DB.prepare(
    `UPDATE orders SET code_hash = ?, code_cipher = ?, code_iv = ?, code_generation = ?, code_attempts = 0, code_resends = ?, code_locked = 0
     WHERE id = ? AND buyer_user_id = ? AND status IN ('paid', 'under_review')`
  ).bind(codeHash, encRes.cipher, encRes.iv, nextGen, nextResends, id, user.id).run();

  if ((res?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'resend_failed');
  }

  await env.DB.prepare(
    'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(generateId('ev_'), id, 'code_resent', user.id, 'buyer', JSON.stringify({ generation: nextGen }), now).run();

  return json({ delivery_code: newCode, code_resends: nextResends }, 200, cors);
}

async function handleCreateDispute(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  assertId(id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? LIMIT 1').bind(id).first();
  if (!order) throw new HttpError(404, 'order_not_found');

  let side = null;
  if (order.buyer_user_id === user.id) side = 'buyer';
  else if (order.seller_user_id === user.id) side = 'seller';
  else throw new HttpError(404, 'order_not_found');

  const body = await readJson(request);
  const reason = String(body.reason || '');
  const message = String(body.message || '').trim();
  if (message.length > 500) throw new HttpError(400, 'message_too_long');

  const validReasons = ['not_delivered', 'item_not_as_described', 'seller_marked_delivered_but_not_received', 'harassment', 'other'];
  if (!validReasons.includes(reason)) throw new HttpError(400, 'invalid_reason');

  const disputeId = generateId('disp_');
  try {
    await env.DB.prepare(
      `INSERT INTO disputes (id, order_id, opened_by_user_id, side, reason, message, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'open', ?)`
    ).bind(disputeId, id, user.id, side, reason, message, now).run();
  } catch (err) {
    if (String(err?.message || '').includes('UNIQUE')) {
      throw new HttpError(409, 'dispute_already_open');
    }
    throw err;
  }

  await env.DB.prepare(
    `UPDATE orders SET status = 'under_review' WHERE id = ? AND status = 'paid'`
  ).bind(id).run();

  await env.DB.prepare(
    'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(generateId('ev_'), id, 'dispute_opened', user.id, side, JSON.stringify({ reason }), now).run();

  return json({ dispute_id: disputeId }, 201, cors);
}

async function handleSellerGetOrders(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  if (user.account_type !== 'seller') throw new HttpError(403, 'wrong_account_type');

  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const cursor = Number(url.searchParams.get('cursor') || now + 99999999);

  let query = `SELECT id, order_number, product_name, buyer_user_id, status, buyer_price_ugx, deposit_ugx, seller_reserve_ugx, balance_due_ugx, deadline_at, created_at
               FROM orders WHERE seller_user_id = ? AND created_at < ?`;
  const binds = [user.id, cursor];

  if (status) {
    query += ' AND status = ?';
    binds.push(status);
  }
  query += ' ORDER BY created_at DESC LIMIT 20';

  const rows = await env.DB.prepare(query).bind(...binds).all();
  const results = rows.results || [];

  const formatted = [];
  for (const r of results) {
    const buyerRow = await env.DB.prepare('SELECT display_name FROM users WHERE id = ?').bind(r.buyer_user_id).first();
    const fullName = buyerRow?.display_name || 'Buyer';
    const firstName = fullName.trim().split(/\s+/)[0] || 'Buyer';

    formatted.push({
      id: r.id,
      order_number: r.order_number,
      product_name: r.product_name,
      buyer_first_name: firstName,
      status: r.status,
      buyer_price_ugx: r.buyer_price_ugx,
      deposit_ugx: r.deposit_ugx,
      seller_reserve_ugx: r.seller_reserve_ugx,
      balance_due_ugx: r.balance_due_ugx,
      deadline_at: r.deadline_at,
      created_at: r.created_at,
    });
  }

  const nextCursor = results.length === 20 ? results[results.length - 1].created_at : null;
  return json({ orders: formatted, next_cursor: nextCursor }, 200, cors);
}

async function handleSellerGetOrderDetail(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const { user } = await requireAuth(request, env, now);
  if (user.account_type !== 'seller') throw new HttpError(403, 'wrong_account_type');
  assertId(id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? AND seller_user_id = ? LIMIT 1')
    .bind(id, user.id).first();
  if (!order) throw new HttpError(404, 'order_not_found');

  let buyerDetails = null;
  const allowedContactStatuses = ['paid', 'delivered', 'under_review'];
  if (allowedContactStatuses.includes(order.status) && Number(order.contact_revoked || 0) === 0) {
    const buyerUser = await env.DB.prepare('SELECT display_name, email FROM users WHERE id = ?').bind(order.buyer_user_id).first();
    const phoneRow = await env.DB.prepare(
      'SELECT phone_e164 FROM user_phones WHERE user_id = ? AND is_primary = 1 AND verified_at IS NOT NULL AND removed_at IS NULL LIMIT 1'
    ).bind(order.buyer_user_id).first();

    buyerDetails = {
      display_name: buyerUser?.display_name || 'Buyer',
      email: buyerUser?.email || '',
      phone: phoneRow?.phone_e164 || '',
    };

    const ipHash = await hmacHex(env, request.headers.get('CF-Connecting-IP') || '127.0.0.1');
    await env.DB.prepare(
      'INSERT INTO order_contact_views (id, order_id, viewer_user_id, ip_hash, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(generateId('cv_'), id, user.id, ipHash, now).run();
  }

  return json({
    order: {
      id: order.id,
      order_number: order.order_number,
      status: order.status,
      product_name: order.product_name,
      business_name: order.business_name,
      delivery_text: order.delivery_text,
      delivery_days: order.delivery_days,
      buyer_price_ugx: order.buyer_price_ugx,
      deposit_ugx: order.deposit_ugx,
      seller_reserve_ugx: order.seller_reserve_ugx,
      balance_due_ugx: order.balance_due_ugx,
      deadline_at: order.deadline_at,
      created_at: order.created_at,
      paid_at: order.paid_at,
      buyer: buyerDetails,
    },
  }, 200, cors);
}

async function handleSellerDeliver(request, env, id, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT']);
  const { user } = await requireAuth(request, env, now);
  if (user.account_type !== 'seller') throw new HttpError(403, 'wrong_account_type');
  assertId(id, 'invalid_order_id');

  const body = await readJson(request);
  const code = String(body.code || '').trim();
  if (!code) throw new HttpError(400, 'invalid_code');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? AND seller_user_id = ? LIMIT 1')
    .bind(id, user.id).first();
  if (!order) throw new HttpError(404, 'order_not_found');
  if (order.status !== 'paid' && order.status !== 'under_review') {
    throw new HttpError(400, 'invalid_order_status');
  }
  if (Number(order.code_locked || 0) === 1) {
    throw new HttpError(423, 'code_locked');
  }

  const providedHash = await hmacHex(env, `code:${id}:${order.code_generation}:${code}`);
  const isMatch = timingSafeEqual(providedHash, order.code_hash);

  if (!isMatch) {
    const upd = await env.DB.prepare(
      `UPDATE orders SET code_attempts = code_attempts + 1,
         code_locked = CASE WHEN code_attempts + 1 >= ? THEN 1 ELSE 0 END
       WHERE id = ? AND code_locked = 0
       RETURNING code_attempts, code_locked`
    ).bind(CODE_MAX_ATTEMPTS, id).run();
    const nextAttempts = Number(upd.results?.[0]?.code_attempts ?? CODE_MAX_ATTEMPTS);
    const lockNow = Number(upd.results?.[0]?.code_locked ?? 1);

    const attemptsLeft = Math.max(0, CODE_MAX_ATTEMPTS - nextAttempts);
    throw new HttpError(400, 'wrong_code', { attempts_left: attemptsLeft, locked: lockNow === 1 });
  }

  const batchOps = [
    env.DB.prepare(
      `UPDATE orders SET status = 'delivered', delivered_at = ? WHERE id = ? AND status IN ('paid', 'under_review') AND code_locked = 0`
    ).bind(now, id),
    env.DB.prepare(
      'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(generateId('ev_'), id, 'delivered', user.id, 'seller', '{}', now),
    env.DB.prepare(
      "INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
    ).bind(
      generateId('ob_'), id, 'ledger_delivered',
      JSON.stringify({
        order_id: id,
        order_number: order.order_number,
        seller_user_id: order.seller_user_id,
        seller_reserve_ugx: order.seller_reserve_ugx,
        product_referee_user_id: order.product_referee_user_id,
        product_referee_payable_ugx: order.product_referee_payable_ugx,
        business_referrer_user_id: order.business_referrer_user_id,
        business_referrer_payable_ugx: order.business_referrer_payable_ugx,
      }),
      now, now
    ),
  ];

  
  const results = await env.DB.batch(batchOps);
  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'delivery_failed');
  }

  return json({ delivered: true }, 200, cors);
}

async function requireAdmin(request, env, now) {
  const { user } = await requireAuth(request, env, now);
  if (Number(user.is_admin || 0) !== 1 || user.status !== 'active') {
    throw new HttpError(403, 'forbidden');
  }
  return user;
}

async function writeAuditLog(env, adminId, action, targetId, metadata, now) {
  const targetType = action === 'resolve_dispute' ? 'dispute' : 'order';
  await env.DB.prepare(
    'INSERT INTO audit_log (id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(generateId('aud_'), adminId, action, targetType, targetId, JSON.stringify(metadata || {}), now).run();
}

async function handleAdminGetOrders(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const cursor = Number(url.searchParams.get('cursor') || now + 99999999);

  let query = 'SELECT id, order_number, buyer_user_id, seller_user_id, business_id, product_id, status, product_name, business_name, price_ugx, discount_ugx, buyer_price_ugx, deposit_ugx, payment_fee_ugx, total_charged_ugx, balance_due_ugx, created_at, paid_at, deadline_at, delivered_at FROM orders WHERE created_at < ?';
  const binds = [cursor];
  if (status) {
    query += ' AND status = ?';
    binds.push(status);
  }
  query += ' ORDER BY created_at DESC LIMIT 20';

  const rows = await env.DB.prepare(query).bind(...binds).all();
  const results = rows.results || [];
  const nextCursor = results.length === 20 ? results[results.length - 1].created_at : null;

  return json({ orders: results, next_cursor: nextCursor }, 200, cors);
}

async function handleAdminGetOrderDetail(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  assertId(id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? LIMIT 1').bind(id).first();
  if (!order) throw new HttpError(404, 'order_not_found');

  const events = await env.DB.prepare('SELECT * FROM order_events WHERE order_id = ? ORDER BY created_at ASC').bind(id).all();
  const disputes = await env.DB.prepare('SELECT * FROM disputes WHERE order_id = ?').bind(id).all();

  return json({
    order: stripInternal(order, false),
    events: events.results || [],
    disputes: disputes.results || [],
  }, 200, cors);
}

async function handleAdminMarkDelivered(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  assertId(id, 'invalid_order_id');

  const body = await readJson(request);
  const note = String(body.note || '');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? LIMIT 1').bind(id).first();
  if (!order) throw new HttpError(404, 'order_not_found');
  if (order.status !== 'paid' && order.status !== 'under_review') {
    throw new HttpError(400, 'invalid_order_status');
  }

  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE orders SET status = 'delivered', delivered_at = ? WHERE id = ? AND status IN ('paid', 'under_review')`
    ).bind(now, id),
    env.DB.prepare(
      'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(generateId('ev_'), id, 'admin_marked_delivered', admin.id, 'admin', JSON.stringify({ note }), now),
    env.DB.prepare(
      "INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
    ).bind(
      generateId('ob_'), id, 'ledger_delivered',
            JSON.stringify({
        order_id: id,
        order_number: order.order_number,
        seller_user_id: order.seller_user_id,
        seller_reserve_ugx: order.seller_reserve_ugx,
        product_referee_user_id: order.product_referee_user_id,
        product_referee_payable_ugx: order.product_referee_payable_ugx,
        business_referrer_user_id: order.business_referrer_user_id,
        business_referrer_payable_ugx: order.business_referrer_payable_ugx,
      }),
      now, now
    ),
  ]);

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'update_failed');
  }

  await writeAuditLog(env, admin.id, 'mark_delivered', id, { note }, now);
  return json({ marked_delivered: true }, 200, cors);
}

async function handleAdminStartRefund(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  assertId(id, 'invalid_order_id');

  const body = await readJson(request);
  const note = String(body.note || '');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? LIMIT 1').bind(id).first();
  if (!order) throw new HttpError(404, 'order_not_found');
  if (order.status !== 'paid' && order.status !== 'under_review' && order.status !== 'delivered') {
    throw new HttpError(400, 'invalid_order_status');
  }

  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE orders SET status = 'refund_pending' WHERE id = ? AND status IN ('paid', 'under_review', 'delivered')`
    ).bind(id),
    env.DB.prepare(
      'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(generateId('ev_'), id, 'start_refund', admin.id, 'admin', JSON.stringify({ note }), now),
    env.DB.prepare(
      "INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
    ).bind(
      generateId('ob_'), id, 'ledger_refund_due',
      JSON.stringify({
        order_id: id,
        order_number: order.order_number,
        buyer_user_id: order.buyer_user_id,
        deposit_ugx: order.deposit_ugx,
        payment_fee_ugx: order.payment_fee_ugx,
        total_charged_ugx: order.total_charged_ugx,
      }),
      now, now
    ),
  ]);

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'refund_start_failed');
  }

  await writeAuditLog(env, admin.id, 'start_refund', id, { note }, now);
  return json({ refund_pending: true }, 200, cors);
}

async function handleAdminRecordRefund(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  assertId(id, 'invalid_order_id');

  const body = await readJson(request);
  const pesapalRef = String(body.pesapal_ref || '').trim();
  if (!pesapalRef) throw new HttpError(400, 'invalid_pesapal_ref');

  const results = await env.DB.batch([
    env.DB.prepare("UPDATE orders SET status = 'refunded' WHERE id = ? AND status = 'refund_pending'").bind(id),
    env.DB.prepare(
      'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(generateId('ev_'), id, 'record_refund', admin.id, 'admin', JSON.stringify({ pesapal_ref: pesapalRef }), now),
  ]);

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'record_refund_failed');
  }

  await writeAuditLog(env, admin.id, 'record_refund', id, { pesapal_ref: pesapalRef }, now);
  return json({ refunded: true }, 200, cors);
}

async function handleAdminRevokeContact(request, env, id, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  assertId(id, 'invalid_order_id');

  const res = await env.DB.prepare('UPDATE orders SET contact_revoked = 1 WHERE id = ?').bind(id).run();
  if ((res?.meta?.changes ?? 0) !== 1) throw new HttpError(404, 'order_not_found');

  await writeAuditLog(env, admin.id, 'revoke_contact', id, {}, now);
  return json({ contact_revoked: true }, 200, cors);
}

async function handleAdminResolveDispute(request, env, disputeId, now, cors) {
  assertEnv(env, ['DB']);
  const admin = await requireAdmin(request, env, now);
  assertId(disputeId, 'invalid_dispute_id');

  const body = await readJson(request);
  const resolution = String(body.resolution || '');
  const note = String(body.note || '');

  const res = await env.DB.prepare(
    `UPDATE disputes SET status = 'resolved', resolution = ?, resolved_by = ?, resolved_at = ? WHERE id = ? AND status = 'open'`
  ).bind(resolution, admin.id, now, disputeId).run();

  if ((res?.meta?.changes ?? 0) !== 1) throw new HttpError(404, 'dispute_not_found');

  await writeAuditLog(env, admin.id, 'resolve_dispute', disputeId, { resolution, note }, now);
  return json({ resolved: true }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* Internal Endpoints                                                 */
/* ------------------------------------------------------------------ */

async function handleInternalOrderPayable(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const orderId = assertId(body.order_id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT id, status, total_charged_ugx, buyer_user_id, order_number, expires_at FROM orders WHERE id = ? LIMIT 1')
    .bind(orderId).first();

  if (!order || order.status !== 'awaiting_payment' || order.expires_at <= now) {
    throw new HttpError(409, 'order_not_payable');
  }

  return json({
    order_id: order.id,
    status: order.status,
    total_charged_ugx: order.total_charged_ugx,
    buyer_user_id: order.buyer_user_id,
    order_number: order.order_number,
  }, 200, {});
}

async function handleInternalPaymentConfirmed(request, env, now) {
  assertEnv(env, ['DB', 'CODE_ENC_KEY', 'HASH_SALT']);
  await requireInternal(request, env);
  const body = await readJson(request);
  const orderId = assertId(body.order_id, 'invalid_order_id');
  const paymentId = assertId(body.payment_id, 'invalid_payment_id');
  const amountUgx = Number(body.amount_ugx);

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? LIMIT 1').bind(orderId).first();
  if (!order) throw new HttpError(404, 'order_not_found');

  const dup = await env.DB.prepare('SELECT id FROM orders WHERE payment_id = ? LIMIT 1').bind(paymentId).first();
  if (dup) {
    return json({ confirmed: true, duplicate: true }, 200, {});
  }

  if (amountUgx !== Number(order.total_charged_ugx)) {
    await env.DB.prepare(
      'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(generateId('ev_'), orderId, 'payment_amount_mismatch', null, 'system', JSON.stringify({ expected: order.total_charged_ugx, received: amountUgx }), now).run();
    throw new HttpError(409, 'amount_mismatch');
  }

  const plainCode = generateDeliveryCode();
  const codeHash = await hmacHex(env, `code:${orderId}:1:${plainCode}`);
  const encRes = await encryptCode(env, plainCode);
  const deliveryDays = Number(order.delivery_days || 3);
  const deadlineAt = now + deliveryDays * 86400;

  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE orders SET status = 'paid', paid_at = ?, deadline_at = ?, payment_id = ?, code_hash = ?, code_cipher = ?, code_iv = ?
       WHERE id = ? AND payment_id IS NULL`
    ).bind(now, deadlineAt, paymentId, codeHash, encRes.cipher, encRes.iv, orderId),
    env.DB.prepare(
      'INSERT INTO order_events (id, order_id, event, actor_user_id, actor_role, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(generateId('ev_'), orderId, 'payment_confirmed', null, 'system', JSON.stringify({ payment_id: paymentId }), now),
    env.DB.prepare(
      "INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
    ).bind(
      generateId('ob_'), orderId, 'ledger_deposit_received',
      JSON.stringify({
        order_id: orderId,
        order_number: order.order_number,
        buyer_user_id: order.buyer_user_id,
        deposit_ugx: order.deposit_ugx,
        payment_fee_ugx: order.payment_fee_ugx,
        payment_id: paymentId,
      }),
      now, now
    ),
    env.DB.prepare(
      "INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
    ).bind(
      generateId('ob_'), orderId, 'feed_buy',
      JSON.stringify({ user_id: order.buyer_user_id, type: 'buy', product_id: order.product_id, ref: orderId }),
      now, now
    ),
    ...(order.product_referee_user_id
      ? [env.DB.prepare("INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)").bind(
          generateId('ob_'), orderId, 'slot_activate',
          JSON.stringify({ product_id: order.product_id, referee_user_id: order.product_referee_user_id, payment_id: paymentId }),
          now, now)]
      : []),
    ...(order.discount_id
      ? [env.DB.prepare("INSERT INTO order_outbox (id, order_id, kind, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)").bind(
          generateId('ob_'), orderId, 'discount_consume',
          JSON.stringify({ discount_id: order.discount_id, buyer_user_id: order.buyer_user_id, order_ref: orderId }),
          now, now)]
      : []),
  ]);

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'payment_already_recorded');
  }

  return json({ confirmed: true, duplicate: false }, 200, {});
}

async function handleInternalReceiptEmail(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const orderId = assertId(body.order_id, 'invalid_order_id');

  const order = await env.DB.prepare('SELECT * FROM orders WHERE id = ? LIMIT 1').bind(orderId).first();
  if (!order || order.status !== 'paid') {
    throw new HttpError(404, 'order_not_found');
  }

  const buyer = await env.DB.prepare('SELECT email, display_name FROM users WHERE id = ?').bind(order.buyer_user_id).first();
  const sellerUser = await env.DB.prepare('SELECT display_name FROM users WHERE id = ?').bind(order.seller_user_id).first();

  let plainCode = '';
  if (order.code_cipher && order.code_iv) {
    try {
      plainCode = await decryptCode(env, order.code_cipher, order.code_iv);
    } catch {}
  }

  if (!plainCode) throw new HttpError(500, 'code_unavailable');
  const buyerFirstName = (buyer?.display_name || 'Buyer').trim().split(/\s+/)[0];
  const sellerName = sellerUser?.display_name || order.business_name;
  const orderDate = formatDate(order.created_at);

  let discountRowHtml = '';
  let discountRowText = '';
  if (Number(order.discount_ugx || 0) > 0) {
    discountRowHtml = `<tr>
      <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Discount</td>
      <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">- UGX ${formatUgx(order.discount_ugx)}</td>
    </tr>`;
    discountRowText = `Discount: - UGX ${formatUgx(order.discount_ugx)}\n`;
  }

  let logoUrl = env.RECEIPT_LOGO_URL || '';
  if (!logoUrl.startsWith('https://')) logoUrl = '';

  const html = getReceiptHtml({
    logo_url: logoUrl,
    order_number: order.order_number,
    order_date: orderDate,
    buyer_first_name: buyerFirstName,
    delivery_code: plainCode,
    product_name: order.product_name,
    seller_name: sellerName,
    delivery_text: order.delivery_text,
    delivery_days: order.delivery_days,
    item_price: formatUgx(order.price_ugx),
    discount_row: discountRowHtml,
    deposit: formatUgx(order.deposit_ugx),
    payment_fee: formatUgx(order.payment_fee_ugx),
    total_paid: formatUgx(order.total_charged_ugx),
    balance_due: formatUgx(order.balance_due_ugx),
    order_url: `https://earnityug.com/orders/${order.order_number}`,
  });

  const text = `Your Earnity order ${order.order_number} is confirmed.
Hello ${buyerFirstName}, we received your deposit.
Delivery Code: ${plainCode}

Item: ${order.product_name}
Seller: ${sellerName}
Delivery: ${order.delivery_text} Expected within ${order.delivery_days} days.

Item price: UGX ${formatUgx(order.price_ugx)}
${discountRowText}Deposit: UGX ${formatUgx(order.deposit_ugx)}
Payment fee: UGX ${formatUgx(order.payment_fee_ugx)}
Paid today: UGX ${formatUgx(order.total_charged_ugx)}

Balance due to seller on delivery: UGX ${formatUgx(order.balance_due_ugx)}

View order: https://earnityug.com/orders/${order.order_number}
`;

  return json({
    to: buyer?.email || '',
    subject: `Your Earnity order ${order.order_number} is confirmed`,
    html,
    text,
  }, 200, {});
}

async function handleInternalSweep(request, env, now) {
  assertEnv(env, ['DB']);
  await requireInternal(request, env);

  const expRes = await env.DB.prepare(
    "UPDATE orders SET status = 'expired' WHERE status = 'awaiting_payment' AND expires_at <= ?"
  ).bind(now).run();

  const revRes = await env.DB.prepare(
    "UPDATE orders SET status = 'under_review' WHERE status = 'paid' AND deadline_at <= ?"
  ).bind(now).run();

  return json({
    expired_orders: expRes?.meta?.changes || 0,
    review_orders: revRes?.meta?.changes || 0,
  }, 200, {});
}

async function handleInternalOutboxProcess(request, env, now) {
  assertEnv(env, ['DB', 'INTERNAL_KEY']);
  await requireInternal(request, env);

  const rows = await env.DB.prepare(
    "SELECT * FROM order_outbox WHERE status = 'pending' AND kind NOT LIKE 'ledger_%' AND next_attempt_at <= ? LIMIT 20"
  ).bind(now).all();

  let processed = 0;
  for (const row of rows.results || []) {
    const payload = JSON.parse(row.payload || '{}');
    let success = false;
    try {
      if (row.kind === 'slot_activate') {
        await callService(env.CATALOG, '/internal/slot-activate', payload, env);
        success = true;
      } else if (row.kind === 'discount_consume') {
        await callService(env.REFERRALS, '/internal/discount-consume', payload, env);
        success = true;
      } else if (row.kind === 'feed_buy') {
        await callService(env.FEED, '/internal/event', payload, env);
        success = true;
      }
    } catch {
      success = false;
    }

    if (success) {
      await env.DB.prepare("UPDATE order_outbox SET status = 'done', done_at = ? WHERE id = ?").bind(now, row.id).run();
      processed++;
    } else {
      const attempts = Number(row.attempts || 0) + 1;
      if (attempts >= 10) {
        await env.DB.prepare("UPDATE order_outbox SET status = 'failed', attempts = ? WHERE id = ?").bind(attempts, row.id).run();
      } else {
        const nextAttempt = now + 60 * Math.pow(2, attempts);
        await env.DB.prepare("UPDATE order_outbox SET attempts = ?, next_attempt_at = ? WHERE id = ?").bind(attempts, nextAttempt, row.id).run();
      }
    }
  }

  return json({ processed }, 200, {});
}

async function handleInternalOutboxPull(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const prefix = String(body.kind_prefix || 'ledger_');
  const limit = Math.min(Number(body.limit || 20), 50);

  const rows = await env.DB.prepare(
    "SELECT * FROM order_outbox WHERE kind LIKE ? AND status = 'pending' LIMIT ?"
  ).bind(prefix + '%', limit).all();

  return json({ rows: rows.results || [] }, 200, {});
}

async function handleInternalOutboxAck(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const ids = body.ids;
  if (!Array.isArray(ids) || ids.length === 0) throw new HttpError(400, 'invalid_ids');

  for (const id of ids) assertId(id);

  for (const id of ids) {
    await env.DB.prepare("UPDATE order_outbox SET status = 'done', done_at = ? WHERE id = ?").bind(now, id).run();
  }

  return json({ acknowledged: true }, 200, {});
}

/* ------------------------------------------------------------------ */
/* Embedded Receipt Template Engine                                   */
/* ------------------------------------------------------------------ */

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getReceiptHtml(p) {
  const safeLogoUrl = escapeHtml(p.logo_url);
  const safeOrderNumber = escapeHtml(p.order_number);
  const safeOrderDate = escapeHtml(p.order_date);
  const safeBuyerFirstName = escapeHtml(p.buyer_first_name);
  const safeDeliveryCode = escapeHtml(p.delivery_code);
  const safeProductName = escapeHtml(p.product_name);
  const safeSellerName = escapeHtml(p.seller_name);
  const safeDeliveryText = escapeHtml(p.delivery_text);
  const safeDeliveryDays = escapeHtml(p.delivery_days);
  const safeItemPrice = escapeHtml(p.item_price);
  const safeDeposit = escapeHtml(p.deposit);
  const safePaymentFee = escapeHtml(p.payment_fee);
  const safeTotalPaid = escapeHtml(p.total_paid);
  const safeBalanceDue = escapeHtml(p.balance_due);
  const safeOrderUrl = escapeHtml(p.order_url);
  const discountRowHtml = p.discount_row || '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light only">
<meta name="supported-color-schemes" content="light only">
<title>Your Earnity order ${safeOrderNumber}</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f4f2;">

<div style="display:none;max-height:0;overflow:hidden;font-size:1px;line-height:1px;color:#f1f4f2;">
Your order is confirmed. Your delivery code is inside. Share it with the seller only when your item arrives.
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f4f2" style="background-color:#f1f4f2;">
<tr>
<td align="center" style="padding:20px 10px;">

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">

    <tr>
      <td bgcolor="#064e3b" style="background-color:#064e3b;padding:22px 28px;border-radius:12px 12px 0 0;">
        <img src="${safeLogoUrl}" alt="Earnity" width="140" style="display:block;border:0;outline:none;text-decoration:none;height:auto;max-width:140px;font-family:Georgia,'Times New Roman',serif;font-size:26px;line-height:30px;color:#ffffff;font-weight:bold;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;color:#a7d9c4;padding-top:6px;">Refer, earn, save.</div>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:28px 28px 8px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:22px;line-height:28px;color:#0f1f19;font-weight:bold;">Your order is confirmed</div>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#4b5b54;padding-top:6px;">
          Hello ${safeBuyerFirstName}, we received your deposit. Order ${safeOrderNumber} &middot; ${safeOrderDate}
        </div>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:16px 28px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td align="center" bgcolor="#ecf7f1" style="background-color:#ecf7f1;border:2px solid #064e3b;border-radius:10px;padding:20px 12px;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:20px;color:#1f3a30;">Your delivery code</div>
              <div style="font-family:'Courier New',Courier,monospace;font-size:38px;line-height:46px;letter-spacing:8px;color:#064e3b;font-weight:bold;padding:6px 0;">${safeDeliveryCode}</div>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:19px;color:#1f3a30;">
                Tell this code to the seller only when your item is in your hands.<br>
                Never share it before delivery, and never send it by message. Earnity staff will never ask for it.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:12px 28px 4px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:22px;color:#0f1f19;font-weight:bold;padding-bottom:8px;">What you ordered</div>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#0f1f19;">
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;" width="38%" valign="top">Item</td>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;" valign="top">${safeProductName}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;" valign="top">Seller</td>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;" valign="top">${safeSellerName}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#4b5b54;" valign="top">Delivery</td>
            <td style="padding:6px 0;" valign="top">${safeDeliveryText} Expected within ${safeDeliveryDays} days.</td>
          </tr>
        </table>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:16px 28px 4px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:22px;color:#0f1f19;font-weight:bold;padding-bottom:8px;">Your payment</div>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#0f1f19;">
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Item price</td>
            <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">UGX ${safeItemPrice}</td>
          </tr>
          ${discountRowHtml}
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Deposit</td>
            <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">UGX ${safeDeposit}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Payment fee</td>
            <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">UGX ${safePaymentFee}</td>
          </tr>
          <tr>
            <td style="padding:8px 0;font-weight:bold;">Paid today</td>
            <td align="right" style="padding:8px 0;font-weight:bold;">UGX ${safeTotalPaid}</td>
          </tr>
        </table>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#6b7a73;padding-top:2px;">The payment fee is charged for processing mobile money and card payments.</div>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:16px 28px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td bgcolor="#f1f4f2" style="background-color:#f1f4f2;border-radius:8px;padding:14px 16px;font-family:Arial,Helvetica,sans-serif;">
              <div style="font-size:13px;line-height:19px;color:#4b5b54;">To pay the seller when your item arrives</div>
              <div style="font-size:22px;line-height:28px;color:#0f1f19;font-weight:bold;">UGX ${safeBalanceDue}</div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:4px 28px 8px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:22px;color:#0f1f19;font-weight:bold;padding-bottom:6px;">What happens next</div>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:22px;color:#0f1f19;">
          1. The seller prepares your order and delivers it.<br>
          2. You check the item, then pay the balance to the seller.<br>
          3. You tell the seller your code, and they confirm delivery in their Earnity account.
        </div>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:22px;color:#0f1f19;padding-top:10px;">
          If the seller does not deliver, you will be refunded.
        </div>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" align="center" style="background-color:#ffffff;padding:16px 28px 28px 28px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td align="center" bgcolor="#064e3b" style="background-color:#064e3b;border-radius:8px;">
              <a href="${safeOrderUrl}" style="display:inline-block;padding:13px 28px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:20px;color:#ffffff;text-decoration:none;font-weight:bold;">View your order</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <tr>
      <td bgcolor="#e6ece9" style="background-color:#e6ece9;padding:18px 28px;border-radius:0 0 12px 12px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:19px;color:#4b5b54;">
          The seller can see your name, phone and email for this order. Keep this email safe, it holds your delivery code.<br><br>
          Need help: <a href="mailto:support@earnityug.com" style="color:#064e3b;">support@earnityug.com</a><br>
          Report a problem or suspected fraud: <a href="mailto:report@earnityug.com" style="color:#064e3b;">report@earnityug.com</a><br>
          General questions: <a href="mailto:inquiry@earnityug.com" style="color:#064e3b;">inquiry@earnityug.com</a><br>
          More ways to reach us: <a href="https://earnityug.com/contacts.html" style="color:#064e3b;">earnityug.com/contacts.html</a><br><br>
          Earnity &middot; earnityug.com
        </div>
      </td>
    </tr>

  </table>

</td>
</tr>
</table>

</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* Worker Entrypoint                                                  */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    const now = Math.floor(Date.now() / 1000);
    const origin = request.headers.get('Origin');

    if (origin && !isAllowedOrigin(origin)) {
      return json({ error: 'origin_not_allowed' }, 403, {});
    }

    const cors = corsHeaders(origin);
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/internal/') && origin) {
      return json({ error: 'forbidden' }, 403, {});
    }

    if (request.method === 'OPTIONS') {
      if (path.startsWith('/internal/')) return json({ error: 'forbidden' }, 403, {});
      return new Response(null, {
        status: 204,
        headers: { ...cors, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
      });
    }

    try {
      if (path === '/health' && request.method === 'GET') return await handleHealth(env, now, cors);
      if (path === '/orders' && request.method === 'POST') return await handleCreateOrder(request, env, now, cors);
      if (path === '/orders' && request.method === 'GET') return await handleGetOrdersBuyer(request, env, now, cors);

      let m = path.match(/^\/orders\/([^/]+)$/);
      if (m && request.method === 'GET') return await handleGetOrderDetailBuyer(request, env, m[1], now, cors);

      m = path.match(/^\/orders\/([^/]+)\/cancel$/);
      if (m && request.method === 'POST') return await handleCancelOrder(request, env, m[1], now, cors);

      m = path.match(/^\/orders\/([^/]+)\/code\/resend$/);
      if (m && request.method === 'POST') return await handleResendCode(request, env, m[1], now, cors);

      m = path.match(/^\/orders\/([^/]+)\/dispute$/);
      if (m && request.method === 'POST') return await handleCreateDispute(request, env, m[1], now, cors);

      if (path === '/seller/orders' && request.method === 'GET') return await handleSellerGetOrders(request, env, now, cors);
      m = path.match(/^\/seller\/orders\/([^/]+)$/);
      if (m && request.method === 'GET') return await handleSellerGetOrderDetail(request, env, m[1], now, cors);

      m = path.match(/^\/seller\/orders\/([^/]+)\/deliver$/);
      if (m && request.method === 'POST') return await handleSellerDeliver(request, env, m[1], now, cors);

      if (path === '/admin/orders' && request.method === 'GET') return await handleAdminGetOrders(request, env, now, cors);
      m = path.match(/^\/admin\/orders\/([^/]+)$/);
      if (m && request.method === 'GET') return await handleAdminGetOrderDetail(request, env, m[1], now, cors);

      m = path.match(/^\/admin\/orders\/([^/]+)\/mark-delivered$/);
      if (m && request.method === 'POST') return await handleAdminMarkDelivered(request, env, m[1], now, cors);

      m = path.match(/^\/admin\/orders\/([^/]+)\/start-refund$/);
      if (m && request.method === 'POST') return await handleAdminStartRefund(request, env, m[1], now, cors);

      m = path.match(/^\/admin\/orders\/([^/]+)\/record-refund$/);
      if (m && request.method === 'POST') return await handleAdminRecordRefund(request, env, m[1], now, cors);

      m = path.match(/^\/admin\/orders\/([^/]+)\/revoke-contact$/);
      if (m && request.method === 'POST') return await handleAdminRevokeContact(request, env, m[1], now, cors);

      m = path.match(/^\/admin\/disputes\/([^/]+)\/resolve$/);
      if (m && request.method === 'POST') return await handleAdminResolveDispute(request, env, m[1], now, cors);

      /* Internal */
      if (path === '/internal/order-payable' && request.method === 'POST') return await handleInternalOrderPayable(request, env, now);
      if (path === '/internal/payment-confirmed' && request.method === 'POST') return await handleInternalPaymentConfirmed(request, env, now);
      if (path === '/internal/receipt-email' && request.method === 'POST') return await handleInternalReceiptEmail(request, env, now);
      if (path === '/internal/sweep' && request.method === 'POST') return await handleInternalSweep(request, env, now);
      if (path === '/internal/outbox/process' && request.method === 'POST') return await handleInternalOutboxProcess(request, env, now);
      if (path === '/internal/outbox/pull' && request.method === 'POST') return await handleInternalOutboxPull(request, env, now);
      if (path === '/internal/outbox/ack' && request.method === 'POST') return await handleInternalOutboxAck(request, env, now);

      return json({ error: 'not_found' }, 404, cors);
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ error: err.code, ...(err.extra || {}) }, err.status, cors);
      }
            if (String(err?.message || '').includes('UNIQUE constraint failed: order_outbox')) {
        return json({ error: 'already_processed' }, 409, cors);
      }
      console.error('unhandled_error', { name: err?.name, message: err?.message, stack: err?.stack });
      return json({ error: 'server_error' }, 500, cors);
    }
  },
};
