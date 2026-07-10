import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:3000";

const PROXIED_PREFIXES = [
  "/api",
  "/oidc",
  "/saml",
  "/assets",
  "/health",
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

// In production, the backend serves the build assets under /static/assets/*
// and serves dist/index.html on the canonical SPA routes ("/",
// "/oidc/service-providers", ...) via an explicit allow-list. Setting `base`
// to "/static/" during `vite build` makes dist/index.html reference
// /static/assets/... which matches the Node handler.
// The /vite/* prefix is still served as a temporary alias by the backend to
// preserve older bookmarks and existing integration tests.
// In dev, the Vite dev server keeps `base: /` so navigating directly to
// http://127.0.0.1:5173/ hits the dashboard as before.
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
