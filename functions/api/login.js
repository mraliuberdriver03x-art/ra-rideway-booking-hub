// RA Rideway | Cloudflare Pages Function
// File location: functions/api/login.js
// Requires D1 binding DB, ra_customers, ra_sessions and TURNSTILE_SECRET.

const headers = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer'
};

function message(text, status) {
  return Response.json({ message: text }, { status, headers });
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}

async function passwordMatches(password, stored) {
  // Registration uses pbkdf2-sha256$310000$SALT$HASH.
  const fields = String(stored || '').split('$');
  if (fields.length !== 4 || fields[0] !== 'pbkdf2-sha256' ||
      fields[1] !== '310000') return false;
  try {
    const salt = fromBase64(fields[2]);
    const expected = fromBase64(fields[3]);
    if (salt.length !== 16 || expected.length !== 32) return false;
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const actual = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', iterations: 310000, salt },
      key, 256
    ));
    let difference = 0;
    for (let i = 0; i < expected.length; i++) {
      difference |= actual[i] ^ expected[i];
    }
    return difference === 0;
  } catch {
    return false;
  }
}

async function validateTurnstile(token, request, env) {
  if (!token || token.length > 2048) return false;
  try {
    const response = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET,
          response: token,
          remoteip: request.headers.get('CF-Connecting-IP') || ''
        })
      }
    );
    if (!response.ok) return false;
    const result = await response.json();
    return result.success === true &&
      result.hostname === new URL(env.PUBLIC_SITE_URL).hostname;
  } catch {
    return false;
  }
}

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(text)
  ));
  return [...digest].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.TURNSTILE_SECRET || !env.PUBLIC_SITE_URL) {
    return message('Login is being configured.', 503);
  }
  let allowedOrigin;
  try {
    const site = new URL(env.PUBLIC_SITE_URL);
    if (site.protocol !== 'https:') throw Error('HTTPS required');
    allowedOrigin = site.origin;
  } catch {
    return message('Login is being configured.', 503);
  }
  if (request.headers.get('Origin') !== allowedOrigin) {
    return message('Request not permitted.', 403);
  }
  if (!request.headers.get('Content-Type')?.includes('application/json')) {
    return message('JSON required.', 415);
  }
  if (Number(request.headers.get('Content-Length') || 0) > 8192) {
    return message('Request too large.', 413);
  }

  let data;
  try {
    const text = await request.text();
    if (text.length > 8192) return message('Request too large.', 413);
    data = JSON.parse(text);
  } catch {
    return message('Invalid request.', 400);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return message('Invalid request.', 400);
  }
  const email = String(data.email || '').trim().toLowerCase();
  const password = String(data.password || '');
  const turnstileToken = String(data.turnstileToken || '');
  if (!email || email.length > 254 || !password || password.length > 128) {
    return message('Invalid login details.', 400);
  }
  if (!await validateTurnstile(turnstileToken, request, env)) {
    return message('Security check failed. Please retry.', 403);
  }

  let customer;
  try {
    customer = await env.DB.prepare(
      'SELECT id, password_hash, email_verified FROM ra_customers WHERE email = ?'
    ).bind(email).first();
  } catch {
    return message('Login database is not ready.', 503);
  }

  // Still perform a password hash on unknown emails to reduce timing leaks.
  const fakeHash = 'pbkdf2-sha256$310000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const correct = await passwordMatches(password, customer?.password_hash || fakeHash);
  if (!customer || !correct || customer.email_verified !== 1) {
    return message('Incorrect email or password, or account not verified.', 401);
  }

  const random = crypto.getRandomValues(new Uint8Array(32));
  const sessionToken = btoa(String.fromCharCode(...random))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const tokenHash = await sha256Hex(sessionToken);
  const maxAge = 7 * 24 * 60 * 60;
  const expiresAt = Math.floor(Date.now() / 1000) + maxAge;
  try {
    await env.DB.prepare(
      'INSERT INTO ra_sessions (token_hash, customer_id, expires_at) VALUES (?, ?, ?)'
    ).bind(tokenHash, customer.id, expiresAt).run();
  } catch {
    return message('Login sessions are not configured yet.', 503);
  }

  return Response.json(
    { message: 'Signed in successfully.', authenticated: true },
    {
      status: 200,
      headers: {
        ...headers,
        'Set-Cookie': `__Host-ra_session=${sessionToken}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`
      }
    }
  );
}
