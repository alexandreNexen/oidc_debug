/**
 * Integration test locking in the Vite dev configuration for the SPA.
 *
 * Regression guard for the "/static/assets/<hash>.js 404" bug:
 * previously PROXIED_PREFIXES included "/oidc" and "/saml", so navigating
 * to http://127.0.0.1:5173/oidc/service-providers proxied the request to
 * the backend, which returned its production dist/index.html referencing
 * /static/assets/<hash>.{js,css}. Vite dev could not serve those hashed
 * assets, producing a broken page.
 *
 * This test boots the real Vite dev binary in isolation (no backend) and
 * asserts:
 *   1. GET /            -> 200 HTML that references /src/main.jsx (source,
 *                          not a built /static/assets/<hash>.js).
 *   2. GET /oidc/service-providers
 *                        -> same HTML (SPA fallback), still /src/main.jsx.
 *   3. GET /static/assets/anything.js
 *                        -> not served (404 or non-JS) — proves dev never
 *                          leaks a production asset path.
 *
 * The test picks a random free port and passes it via `--port` so it can
 * run in parallel with a real Vite dev server on 5173. Because vite.config.js
 * pins strictPort: true, --port is honored exactly (no fallback).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { after, before, describe, it } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = path.resolve(__dirname, "..", "frontend");
const VITE_BIN = path.join(FRONTEND_DIR, "node_modules", ".bin", "vite");

let child = null;
let baseUrl = "";

function pickPort() {
  return 40000 + Math.floor(Math.random() * 15000);
}

async function waitForRoot(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/`, { headers: { accept: "text/html" } });
      if (res.ok) return;
      lastError = new Error(`unexpected status ${res.status}`);
    } catch (err) {
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Vite dev server did not come up in time: ${lastError?.message || "unknown"}`);
}

before(async () => {
  const port = pickPort();
  baseUrl = `http://127.0.0.1:${port}`;

  child = spawn(VITE_BIN, ["--host", "127.0.0.1", "--port", String(port), "--strictPort"], {
    cwd: FRONTEND_DIR,
    env: { ...process.env, BROWSER: "none", CI: "1" },
    stdio: ["ignore", "ignore", "pipe"]
  });

  await waitForRoot(baseUrl);
});

after(() => {
  if (child) {
    child.kill("SIGTERM");
  }
});

describe("Vite dev server — SPA routing and asset boundary", () => {
  it("GET / returns HTML that references /src/main.jsx (dev source, not a built bundle)", async () => {
    const res = await fetch(`${baseUrl}/`, { headers: { accept: "text/html" } });
    assert.strictEqual(res.status, 200);
    const contentType = res.headers.get("content-type") || "";
    assert.ok(contentType.includes("text/html"), `expected HTML, got ${contentType}`);

    const body = await res.text();
    assert.match(body, /\/src\/main\.jsx/);
    assert.doesNotMatch(body, /\/static\/assets\//);
  });

  it("GET /oidc/service-providers falls through to the same SPA HTML (dev source)", async () => {
    const res = await fetch(`${baseUrl}/oidc/service-providers`, { headers: { accept: "text/html" } });
    assert.strictEqual(res.status, 200);
    const contentType = res.headers.get("content-type") || "";
    assert.ok(contentType.includes("text/html"), `expected HTML, got ${contentType}`);

    const body = await res.text();
    assert.match(body, /\/src\/main\.jsx/);
    assert.doesNotMatch(body, /\/static\/assets\//);
  });

  it("GET /saml/flows/some-id falls through to the same SPA HTML (dev source)", async () => {
    const res = await fetch(`${baseUrl}/saml/flows/some-id`, { headers: { accept: "text/html" } });
    assert.strictEqual(res.status, 200);
    const body = await res.text();
    assert.match(body, /\/src\/main\.jsx/);
    assert.doesNotMatch(body, /\/static\/assets\//);
  });

  it("GET /static/assets/index-fake.js does not exist in dev (no built bundle served)", async () => {
    // Vite dev may return the SPA fallback (index.html) for unknown paths;
    // what matters is that no JS-typed 200 response leaks out — the source
    // of truth in dev is /src/main.jsx, never /static/assets/*.
    const res = await fetch(`${baseUrl}/static/assets/index-fake.js`, {
      headers: { accept: "application/javascript" }
    });
    const contentType = (res.headers.get("content-type") || "").toLowerCase();
    if (res.status === 200) {
      assert.ok(
        !contentType.includes("application/javascript") &&
          !contentType.includes("text/javascript"),
        `dev should never serve /static/assets/* as JS (got ${contentType})`
      );
    }
  });
});
