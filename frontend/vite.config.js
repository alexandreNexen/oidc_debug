import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:3000";

// Only /api/* (and the two backend-owned favicons) are proxied. The SPA
// routes ("/", "/oidc/service-providers", "/saml/flows/:id", ...) MUST NOT
// be proxied in dev: they are handled by Vite's default HTML fallback which
// serves index.html → /src/main.jsx → React. Proxying "/oidc" or "/saml"
// would forward the SPA navigation to the backend, which would return its
// production dist/index.html (referencing /static/assets/<hash>.js) — assets
// that the Vite dev server has no way to serve, producing a 404 chain.
//
// The /health probe is intentionally not proxied: the frontend client uses
// /api/health. Legacy SSR assets under /assets/* are only referenced by the
// SSR views under /legacy/*, which the SPA never renders.
const PROXIED_PREFIXES = [
  "/api",
  "/favicon.svg",
  "/favicon.ico"
];

// xfwd is intentionally false: the backend must build redirect_uri and ACS URLs
// from its canonical BASE_URL, never from the Vite dev host. Forwarding
// X-Forwarded-Host=127.0.0.1:5173 would only contaminate diagnostic UI today,
// but would become a footgun the day any code reads request-derived origin.
function buildProxyConfig() {
  const proxy = {};
  for (const prefix of PROXIED_PREFIXES) {
    proxy[prefix] = {
      target: BACKEND_URL,
      changeOrigin: true,
      secure: false,
      xfwd: false
    };
  }
  return proxy;
}

// Two run modes, distinct base URL:
//   - dev (vite serve):  base: "/"        → index.html loads /src/main.jsx
//   - build (vite build): base: "/static/" → dist/index.html references
//                                             /static/assets/<hash>.{js,css}
//
// In build mode, the backend serves dist/index.html on the canonical SPA
// routes ("/", "/oidc/service-providers", ...) via an explicit allow-list
// (isSpaRoute in src/routes/spa.js) and streams the hashed assets from
// /static/assets/* (src/routes/static.js).
//
// In dev mode, Vite dev is authoritative on port 5173: any HTML navigation
// under an SPA route falls through to Vite's built-in history fallback and
// receives frontend/index.html, which references /src/main.jsx (source).
// The dev server never touches dist/. Rebuilding is not required to see
// changes — HMR does that.
export default defineConfig(({ command }) => ({
  root: ".",
  base: command === "build" ? "/static/" : "/",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: buildProxyConfig()
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy: buildProxyConfig()
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false
  }
}));
