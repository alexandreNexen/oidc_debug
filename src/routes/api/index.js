import { createOidcApiRouter } from "./oidc.js";
import { createSamlApiRouter } from "./saml.js";

// Root JSON API router. Owns the /api/* namespace and enforces the two
// cross-cutting invariants of that namespace:
//
//   1. Cross-site guard for state-changing endpoints.
//      `assertApiPostAllowed` is applied exactly once, here, before
//      delegation to any sub-router. No sub-router repeats the check.
//      IdP callbacks live under /oidc/callback and /saml/acs/:spId,
//      outside /api/, and remain unaffected — the dispatcher in
//      server.js runs them on a separate branch.
//
//   2. Unknown /api/* paths return JSON 404 (not HTML, never the SPA).
//
// /api/health lives here directly instead of in a separate module: the
// handler is a 10-line payload snapshot and giving it a dedicated
// factory would add abstraction without any benefit.

export function createApiRouter(deps) {
  const {
    assertApiPostAllowed,
    http,
    security,
    sessions,
    apiHealth,
    oidc,
    saml
  } = deps;
  const { sendJson } = http;

  const oidcRouter = createOidcApiRouter({ http, security, sessions, oidc });
  const samlRouter = createSamlApiRouter({ http, security, sessions, saml });

  async function handle(req, res, url) {
    if (!url.pathname.startsWith("/api/")) return false;

    // Cross-site guard applied ONCE here so every downstream POST / PATCH
    // / DELETE handler is protected without needing to remember to call
    // the guard itself.
    if (
      (req.method === "POST" || req.method === "PATCH" || req.method === "DELETE") &&
      !assertApiPostAllowed(req, res)
    ) {
      return true;
    }

    if (req.method === "GET" && url.pathname === "/api/health") {
      sendJson(res, 200, apiHealth.getSnapshot());
      return true;
    }

    if (await oidcRouter.handle(req, res, url)) return true;
    if (await samlRouter.handle(req, res, url)) return true;

    sendJson(res, 404, { error: "API route not found." });
    return true;
  }

  return { handle };
}
