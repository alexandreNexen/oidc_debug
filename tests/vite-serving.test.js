/**
 * Integration tests locking in the removal of the /vite/* alias (Lot C).
 *
 * Vite is now served on the canonical routes only ("/", "/oidc/*",
 * "/saml/*"), with build assets under /static/assets/*. The transitional
 * /vite/* alias has been removed. This suite confirms that every /vite/*
 * URL that used to serve the SPA index or an asset now returns 404 JSON.
 *
 * The canonical SPA routing and /static/assets/* live in
 * tests/spa-routing.test.js.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const SERVER_ENTRY = fileURLToPath(new URL("../src/server.js", import.meta.url));

let child = null;
let baseUrl = "";
let storageDir = "";

function pickPort() {
  return 30000 + Math.floor(Math.random() * 20000);
}

async function waitForHealth(url, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("server did not come up in time");
}

before(async () => {
  const port = pickPort();
  baseUrl = `http://127.0.0.1:${port}`;
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-vite-alias-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "vite-alias-test-secret-not-real",
      LOG_LEVEL: "error",
      STORAGE_DIR: storageDir,
      NODE_ENV: "test"
    },
    stdio: ["ignore", "ignore", "pipe"]
  });

  await waitForHealth(baseUrl);
});

after(() => {
  if (child) child.kill("SIGTERM");
  if (storageDir) rmSync(storageDir, { recursive: true, force: true });
});

describe("/vite/* alias has been removed", () => {
  const deprecatedPaths = [
    "/vite",
    "/vite/",
    "/vite/oidc/service-providers",
    "/vite/oidc/flows/some-id",
    "/vite/saml/service-providers",
    "/vite/saml/flows/some-id",
    "/vite/assets/index-does-not-exist.js",
    "/vite/assets/index-does-not-exist.css"
  ];

  for (const path of deprecatedPaths) {
    it(`GET ${path} → 404 (not the SPA index)`, async () => {
      const res = await fetch(`${baseUrl}${path}`);
      assert.strictEqual(res.status, 404);
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("text/html")) {
        // If the 404 response is HTML (unlikely under our default), it must
        // not be the SPA index — the SPA hydration marker must not appear.
        const body = await res.text();
        assert.doesNotMatch(body, /<div id="root"><\/div>/);
      }
    });
  }

  it("POST /vite/ is also 404 (no method-not-allowed shim left over)", async () => {
    const res = await fetch(`${baseUrl}/vite/`, { method: "POST" });
    assert.strictEqual(res.status, 404);
  });
});
