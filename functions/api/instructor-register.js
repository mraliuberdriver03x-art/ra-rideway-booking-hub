
export async function onRequestPost({ request, env }) {
  try {
    const data = await request.json();
    const name = String(data.name || "").trim();
    const email = String(data.email || "").trim().toLowerCase();
    const phone = String(data.phone || "").trim();
    const adiNumber = String(data.adiNumber || "").trim();
    const transmission = String(data.transmission || "").trim();

    if (!name || !email || !phone || !adiNumber ||
        !["manual", "automatic", "both"].includes(transmission)) {
      return Response.json(
        { error: "Please complete all required fields." },
        { status: 400 }
      );
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return Response.json(
        { error: "Invalid email address." },
        { status: 400 }
      );
    }

    if (!env.DB) {
      return Response.json(
        { error: "Database not configured." },
        { status: 503 }
      );
    }

    await env.DB.prepare(
      `INSERT INTO ra_instructors
       (name, email, phone, adi_number, transmission, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    ).bind(name, email, phone, adiNumber, transmission).run();

    return Response.json({
      success: true,
      message: "Application received. Awaiting approval."
    });
  } catch (error) {
    console.error("Instructor registration error:", error);
    return Response.json(
      { error: "Unable to submit application." },
      { status: 500 }
    );
  }
}
