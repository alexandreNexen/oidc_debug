import { readFile } from "node:fs/promises";

// Explicit allow-list of paths the Vite SPA is allowed to render.
// Deliberately NOT a catch-all: /oidc/callback, /saml/acs/:spId,
// /oidc/flows/start/:spId, /saml/flows/start/:spId and every unknown path
// (typos included) must fall through to the backend and NEVER return
// dist/index.html.
export function isSpaRoute(pathname) {
  if (pathname === "/") return true;

  if (pathname === "/oidc/service-providers" || pathname === "/oidc/service-providers/") return true;
  if (pathname === "/oidc/service-providers/new" || pathname === "/oidc/service-providers/new/") return true;
  if (/^\/oidc\/service-providers\/[^/]+\/edit\/?$/.test(pathname)) return true;
  if (pathname === "/oidc/flows" || pathname === "/oidc/flows/") return true;
  if (/^\/oidc\/flows\/[^/]+\/?$/.test(pathname)) return true;

  if (pathname === "/saml/service-providers" || pathname === "/saml/service-providers/") return true;
  if (pathname === "/saml/service-providers/new" || pathname === "/saml/service-providers/new/") return true;
  if (/^\/saml\/service-providers\/[^/]+\/edit\/?$/.test(pathname)) return true;
  if (pathname === "/saml/flows" || pathname === "/saml/flows/") return true;
  if (/^\/saml\/flows\/[^/]+\/?$/.test(pathname)) return true;

  return false;
}

export function createSpaRouter({ viteIndexHtml, send, sendHtmlStatus }) {
  async function serveViteIndex(res) {
    try {
      const html = await readFile(viteIndexHtml, "utf8");
      send(res, 200, html, "text/html; charset=utf-8");
    } catch {
      sendHtmlStatus(
        res,
        503,
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>Vite build missing</title></head><body><h1>Vite frontend not built</h1><p>Run <code>npm run build:frontend</code> before starting the server, or use <code>npm run dev:frontend</code> for development.</p></body></html>"
      );
    }
  }

  async function handleSpaRoute(req, res, url) {
    if (req.method !== "GET" && req.method !== "HEAD") return false;
    if (!isSpaRoute(url.pathname)) return false;
    await serveViteIndex(res);
    return true;
  }

  return { handleSpaRoute, serveViteIndex };
}
