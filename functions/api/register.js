// RA Rideway — Cloudflare Pages Functions
// Save as: functions/api/register.js
// Requires D1 binding DB and ra_customers table from migration.
// Required secrets/configuration:
// TURNSTILE_SECRET, EMAIL_VERIFICATION_SECRET, RESEND_API_KEY,
// RESEND_FROM, PUBLIC_SITE_URL, REGISTRATION_ENABLED="true".

const NO_CACHE = { 'Cache-Control': 'no-store' };

function json(message, status = 200) {
  return Response.json({ message }, { status, headers: NO_CACHE });
}

function page(title, message, status = 200) {
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RA Rideway · ${title}</title></head><body style="font-family:system-ui;background:#101014;color:#f0d18a;padding:2rem">
<h1>${title}</h1><p>${message}</p><p><a style="color:#f0d18a" href="/customer.html">Return to customer portal</a></p></body></html>`;
  return new Response(body, {
    status,
    headers: {
      ...NO_CACHE,
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
      'Referrer-Policy': 'no-referrer'
    }
  });
}

function base64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64url(bytes) {
  return base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signingKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
}

async function makeSignature(secret, value) {
  const key = await signingKey(secret);
  return base64url(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)));
}

async function checkSignature(secret, value, signature) {
  try {
    if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) return false;
    const raw = atob(signature.replace(/-/g, '+').replace(/_/g, '/') + '=');
    const bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
    return crypto.subtle.verify(
      'HMAC', await signingKey(secret), bytes, new TextEncoder().encode(value)
    );
  } catch {
    return false;
  }
}

function validDob(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) &&
    d.toISOString().slice(0, 10) === value &&
    value >= '1900-01-01' && value < new Date().toISOString().slice(0, 10);
}

function configured(env) {
  if (!env.DB || !env.TURNSTILE_SECRET || !env.EMAIL_VERIFICATION_SECRET ||
      !env.RESEND_API_KEY || !env.RESEND_FROM ||
      env.REGISTRATION_ENABLED !== 'true') return false;
  try { return new URL(env.PUBLIC_SITE_URL).protocol === 'https:'; }
  catch { return false; }
}

async function checkTurnstile(token, request, env) {
  try {
    const form = new URLSearchParams({
      secret: env.TURNSTILE_SECRET,
      response: token,
      remoteip: request.headers.get('CF-Connecting-IP') || ''
    });
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', body: form
    });
    if (!response.ok) return false;
    const result = await response.json();
    return result.success === true &&
      result.hostname === new URL(env.PUBLIC_SITE_URL).hostname;
  } catch {
    return false;
  }
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const digest = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 310000 }, key, 256
  );
  return `pbkdf2-sha256$310000$${base64(salt)}$${base64(digest)}`;
}

export async function onRequestPost({ request, env }) {
  if (!configured(env)) return json('Registration is not ready yet.', 503);
  if (!request.headers.get('content-type')?.includes('application/json')) {
    return json('Please send JSON.', 415);
  }
  // Only accept submissions from the configured website in ordinary browsers.
  const origin = request.headers.get('Origin');
  if (origin && origin !== new URL(env.PUBLIC_SITE_URL).origin) {
    return json('Request not permitted.', 403);
  }
  if (Number(request.headers.get('content-length') || 0) > 8192) {
    return json('Request is too large.', 413);
  }
  let data;
  try {
    const body = await request.text();
    if (body.length > 8192) return json('Request is too large.', 413);
    data = JSON.parse(body);
  } catch {
    return json('Invalid request.', 400);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return json('Invalid registration details.', 400);
  }

  const fullName = String(data.full_name || '').trim();
  const dob = String(data.dob || '');
  const phone = String(data.phone || '').trim();
  const email = String(data.email || '').trim().toLowerCase();
  const password = String(data.password || '');
  const turnstileToken = String(data.turnstileToken || '');

  if (fullName.length < 2 || fullName.length > 120 ||
      phone.length < 7 || phone.length > 25 ||
      email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !validDob(dob) || password.length < 12 || password.length > 128 ||
      turnstileToken.length < 1 || turnstileToken.length > 2048) {
    return json('Please check your details. Passwords need at least 12 characters.', 400);
  }
  if (!await checkTurnstile(turnstileToken, request, env)) {
    return json('Security check failed. Please try again.', 403);
  }

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  try {
    await env.DB.prepare(
      `INSERT INTO ra_customers
       (id, full_name, dob, phone, email, password_hash, email_verified)
       VALUES (?, ?, ?, ?, ?, ?, 0)`
    ).bind(id, fullName, dob, phone, email, passwordHash).run();
  } catch (err) {
    // Do not reveal whether a particular email address is registered.
    if (/UNIQUE constraint/i.test(String(err))) {
      return json('If eligible, you will receive an email with next steps.');
    }
    return json('Registration database is not ready. Please try later.', 503);
  }

  const expires = Math.floor(Date.now() / 1000) + 48 * 60 * 60;
  const signature = await makeSignature(env.EMAIL_VERIFICATION_SECRET, `${id}:${expires}`);
  const link = new URL('/api/register', env.PUBLIC_SITE_URL);
  link.searchParams.set('uid', id);
  link.searchParams.set('expires', String(expires));
  link.searchParams.set('sig', signature);

  let sent = false;
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: env.RESEND_FROM,
        to: [email],
        subject: 'Verify your RA Rideway customer account',
        text: `Welcome to RA Rideway. Verify your email within 48 hours:\n\n${link.toString()}\n\nIf you did not register, ignore this email.`
      })
    });
    sent = response.ok;
  } catch {
    sent = false;
  }
  if (!sent) {
    // Roll back this unverified sign-up so the customer may try again.
    try {
      await env.DB.prepare(
        'DELETE FROM ra_customers WHERE id = ? AND email_verified = 0'
      ).bind(id).run();
    } catch { /* leave an unverified record for admin review */ }
    return json('Verification email unavailable. Please try later.', 503);
  }
  return json('Check your email for a verification link.');
}

export async function onRequestGet({ request, env }) {
  if (!env.DB || !env.EMAIL_VERIFICATION_SECRET) {
    return page('Not ready', 'Email verification is unavailable.', 503);
  }
  const params = new URL(request.url).searchParams;
  const uid = params.get('uid') || '';
  const expiresText = params.get('expires') || '';
  const signature = params.get('sig') || '';
  const expires = Number(expiresText);
  if (!/^[0-9a-f-]{36}$/i.test(uid) || !/^\d{10}$/.test(expiresText) ||
      !Number.isSafeInteger(expires) || expires < Date.now() / 1000 ||
      !await checkSignature(env.EMAIL_VERIFICATION_SECRET,
                            `${uid}:${expiresText}`, signature)) {
    return page('Invalid link', 'This verification link is invalid or expired.', 400);
  }
  try {
    const result = await env.DB.prepare(
      'UPDATE ra_customers SET email_verified = 1 WHERE id = ?'
    ).bind(uid).run();
    if (!result.meta?.changes) {
      return page('Account unavailable', 'This account could not be found.', 404);
    }
    return page('Email verified',
      'Your email is verified. Customer login will be available once the secure sign-in system is connected.');
  } catch {
    return page('Not ready', 'Email verification is temporarily unavailable.', 503);
  }
}
