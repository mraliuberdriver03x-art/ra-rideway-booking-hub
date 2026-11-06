
export async function onRequestPost({ env }) {
  if (!env.DB) {
    return Response.json(
      { error: "Database unavailable" },
      { status: 503 }
    );
  }

  return Response.json(
    {
      error: "Registration is being configured. Email verification and secure password authentication are required before accounts can be created."
    },
    {
      status: 503,
      headers: { "Cache-Control": "no-store" }
    }
  );
}
