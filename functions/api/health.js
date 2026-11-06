
export async function onRequestGet(context) {
  try {
    const result = await context.env.DB
      .prepare("SELECT 1 AS ready")
      .first();

    return Response.json({
      database: result?.ready === 1
        ? "connected"
        : "unavailable"
    });
  } catch (error) {
    return Response.json(
      { database: "unavailable" },
      { status: 500 }
    );
  }
}
