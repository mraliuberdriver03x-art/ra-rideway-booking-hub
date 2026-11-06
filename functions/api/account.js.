// RA Rideway - Cloudflare Pages account and booking-request API.
// File path: functions/api/account.js
// Uses the existing DB binding and tables ra_customers, ra_sessions and ra_bookings.
// Booking requests are NOT confirmations, dispatch or payments.

const BASE_HEADERS = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
};

function respond(payload, status = 200, extraHeaders = {}) {
  return Response.json(payload, {
    status,
    headers: { ...BASE_HEADERS, ...extraHeaders }
  });
}

function tokenFromRequest(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)__Host-ra_session=([A-Za-z0-9_-]{43})(?:;|$)/);
  return match ? match[1] : null;
}

async function tokenDigest(token) {
  const bytes = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(token)
  ));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

async function authenticated(request, env) {
  if (!env.DB) return null;
  const token = tokenFromRequest(request);
  if (!token) return null;
  const tokenHash = await tokenDigest(token);
  const now = Math.floor(Date.now() / 1000);
  const customer = await env.DB.prepare(
    `SELECT c.id, c.full_name, c.email, s.token_hash
       FROM ra_sessions AS s
       JOIN ra_customers AS c ON c.id = s.customer_id
      WHERE s.token_hash = ? AND s.expires_at > ? AND c.email_verified = 1
      LIMIT 1`
  ).bind(tokenHash, now).first();
  return customer || null;
}

function originAllowed(request, env) {
  try {
    const site = new URL(env.PUBLIC_SITE_URL);
    return site.protocol === 'https:' && request.headers.get('Origin') === site.origin;
  } catch {
    return false;
  }
}

function expiredCookie() {
  return '__Host-ra_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax';
}

export async function onRequestGet({ request, env }) {
  if (!env.DB) return respond({ message: 'Service unavailable.' }, 503);
  try {
    const customer = await authenticated(request, env);
    if (!customer) return respond({ message: 'Please sign in.' }, 401);
    const bookings = await env.DB.prepare(
      `SELECT id, pickup_location, destination, pickup_at, passengers, status, created_at
         FROM ra_bookings WHERE customer_id = ?
        ORDER BY created_at DESC LIMIT 30`
    ).bind(customer.id).all();
    return respond({
      user: { full_name: customer.full_name, email: customer.email },
      bookings: bookings.results || []
    });
  } catch {
    return respond({ message: 'Account temporarily unavailable.' }, 503);
  }
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) return respond({ message: 'Service unavailable.' }, 503);
  if (!originAllowed(request, env)) return respond({ message: 'Request not permitted.' }, 403);
  if (!request.headers.get('Content-Type')?.includes('application/json')) {
    return respond({ message: 'JSON required.' }, 415);
  }
  let data;
  try {
    const body = await request.text();
    if (body.length > 4096) return respond({ message: 'Request too large.' }, 413);
    data = JSON.parse(body);
  } catch {
    return respond({ message: 'Invalid request.' }, 400);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.action !== 'book') {
    return respond({ message: 'Invalid booking request.' }, 400);
  }

  const pickup = typeof data.pickup_location === 'string' ? data.pickup_location.trim() : '';
  const destination = typeof data.destination === 'string' ? data.destination.trim() : '';
  const when = typeof data.pickup_at === 'string' ? data.pickup_at : '';
  const passengers = data.passengers;
  const epoch = Date.parse(when);
  if (!pickup || pickup.length > 240 || !destination || destination.length > 240 ||
      pickup.toLowerCase() === destination.toLowerCase() ||
      typeof passengers !== 'number' || !Number.isInteger(passengers) ||
      passengers < 1 || passengers > 8 ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(when) ||
      !Number.isFinite(epoch) || epoch < Date.now() + 30 * 60000 ||
      epoch > Date.now() + 365 * 24 * 60 * 60000) {
    return respond({ message: 'Check the journey details. Book at least 30 minutes ahead.' }, 400);
  }
  try {
    const customer = await authenticated(request, env);
    if (!customer) return respond({ message: 'Please sign in again.' }, 401);
    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO ra_bookings
        (id, customer_id, pickup_location, destination, pickup_at, passengers, status)
       VALUES (?, ?, ?, ?, ?, ?, 'requested')`
    ).bind(id, customer.id, pickup, destination, when, passengers).run();
    return respond({
      message: 'Booking request saved. RA Rideway must review and confirm the fare and journey.',
      reference: id
    }, 201);
  } catch {
    return respond({ message: 'Booking service temporarily unavailable.' }, 503);
  }
}

export async function onRequestDelete({ request, env }) {
  if (!originAllowed(request, env)) return respond({ message: 'Request not permitted.' }, 403);
  // Clear the browser cookie even if the database cannot be contacted.
  try {
    const token = tokenFromRequest(request);
    if (token && env.DB) {
      const tokenHash = await tokenDigest(token);
      await env.DB.prepare('DELETE FROM ra_sessions WHERE token_hash = ?')
        .bind(tokenHash).run();
    }
  } catch {
    // Always clear the browser-side cookie.
  }
  return respond({ message: 'Signed out.' }, 200, { 'Set-Cookie': expiredCookie() });
}
