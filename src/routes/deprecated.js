// SSR-era POST canonical routes retired as part of the SPA migration. They
// now respond 410 Gone JSON so a caller pinned to the old URL sees a clear
// signal instead of a silent 404 or a stale success. The equivalent write
// endpoint is available under /api/*.
//
// Explicitly listed here — kept in one place so we can grep for them and
// audit them at once. No mutation. Every branch just returns 410.

const DEPRECATED_POST_PATHS = new Set([
  "/oidc/service-providers",
  "/saml/service-providers"
]);

export function matchDeprecatedPostPath(pathname) {
  if (DEPRECATED_POST_PATHS.has(pathname)) return true;
  if (/^\/oidc\/service-providers\/[^/]+(\/delete)?$/.test(pathname)) return true;
  if (/^\/oidc\/flows\/[^/]+\/rerun$/.test(pathname)) return true;
  if (/^\/oidc\/discovery\/import\/(preprod|prod)$/.test(pathname)) return true;
  if (/^\/saml\/service-providers\/[^/]+(\/delete)?$/.test(pathname)) return true;
  return false;
}

export function createDeprecatedRouter({ sendJson }) {
  function handleDeprecatedRoute(req, res, url) {
    if (req.method !== "POST" && req.method !== "PATCH" && req.method !== "DELETE") return false;
    if (!matchDeprecatedPostPath(url.pathname)) return false;

    sendJson(res, 410, {
      error: "This endpoint has been retired. Use the /api/* equivalent."
    });
    return true;
  }

  return { handleDeprecatedRoute };
}
