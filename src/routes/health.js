// GET /health — plain readiness probe. Kept outside the /api/* bloc so it
// remains reachable without any of the cross-site guards. Payload is
// preserved byte-for-byte from the pre-refactor dispatcher; see
// tests/spa-routing.test.js "GET /health stays JSON".
//
// /api/health lives inside the /api/* JSON API and is intentionally NOT
// moved in this lot — it is coupled to the api bloc for the moment.

export function createHealthRouter({ sendJson, getSnapshot }) {
  function handleHealthRoute(req, res, url) {
    if (req.method !== "GET" || url.pathname !== "/health") return false;
    sendJson(res, 200, getSnapshot());
    return true;
  }

  return { handleHealthRoute };
}
