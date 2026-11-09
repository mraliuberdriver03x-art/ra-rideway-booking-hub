
export async function onRequestPost({ request, env }) {
  const reply = (message, status) =>
    Response.json({ error: message }, { status });

  try {
    if (!env.DB || !env.TURNSTILE_SECRET_KEY) {
      return reply("Registration unavailable.", 503);
    }

    const length = Number(request.headers.get("content-length") || 0);
    if (length > 10000) {
      return reply("Request too large.", 413);
    }

    const data = await request.json();

    const name = String(data.name || "").trim();
    const email = String(data.email || "").trim().toLowerCase();
    const phone = String(data.phone || "").trim();
    const adiNumber = String(data.adiNumber || "").trim();
    const transmission = String(data.transmission || "").trim();
    const token = String(data.turnstileToken || "");

    if (
      !name || name.length > 100 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254 ||
      !/^[+0-9 ()-]{7,30}$/.test(phone) ||
      !/^[a-zA-Z0-9 -]{3,30}$/.test(adiNumber) ||
      !["manual", "automatic", "both"].includes(transmission) ||
      !token
    ) {
      return reply("Please check your application details.", 400);
    }

    const verification = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token,
          remoteip: request.headers.get("CF-Connecting-IP") || ""
        })
      }
    );

    if (!verification.ok) {
      return reply("Verification unavailable.", 503);
    }

    const result = await verification.json();

    if (!result.success) {
      return reply("Security verification failed.", 403);
    }

    await env.DB.prepare(
      `INSERT INTO ra_instructors
       (name, email, phone, adi_number, transmission, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    ).bind(
      name, email, phone, adiNumber, transmission
    ).run();

    return Response.json({
      success: true,
      message: "Application submitted for review."
    });

  } catch (error) {
    if (String(error.message || "").includes("UNIQUE")) {
      return reply("An application already exists for this email.", 409);
    }

    console.error("Instructor registration failed:", error);
    return reply("Unable to process application.", 500);
  }
}
