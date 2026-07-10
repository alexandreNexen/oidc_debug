/**
 * Integration tests locking in the /api/* router refactor invariants.
 *
 * The /api/* namespace is now handled by a dedicated router
 * (src/routes/api/*) mounted from server.js. This suite checks the
 * cross-cutting properties of that router that MUST NOT regress:
 *
 *   1. `assertApiPostAllowed` is applied at exactly one level, at the
 *      root of /api/*. Every POST/PATCH/DELETE goes through it, including
 *      requests to unknown /api/* paths — the guard runs BEFORE the 404
 *      fallback.
 *   2. Unknown /api/* paths return JSON 404, never the SPA index, never a
 *      legacy SSR page.
 *   3. Callbacks (/oidc/callback, /saml/acs/:spId) are NOT routed through
 *      the API router.
 *   4. GET /api/health returns the documented JSON snapshot.
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-api-router-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "api-router-test-secret-not-real",
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

describe("GET /api/health returns the documented snapshot", () => {
  it("responds with JSON status ok and required fields", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.strictEqual(body.status, "ok");
    assert.ok(typeof body.timestamp === "string" && body.timestamp.length > 0);
    assert.ok(typeof body.nodeEnv === "string");
    assert.ok(body.counts && typeof body.counts === "object");
    assert.ok(body.counts.oidc && typeof body.counts.oidc.serviceProviders === "number");
    assert.ok(body.counts.saml && typeof body.counts.saml.serviceProviders === "number");
  });
});

describe("Cross-site guard applies to EVERY POST/PATCH/DELETE /api/*, including unknown paths", () => {
  // Unknown /api/* POST must be caught by the guard BEFORE the 404 fallback.
  // Locks in the "guard applied once, at the root" invariant: if the guard
  // were per-endpoint, unknown /api/* paths would leak through as 404 even
  // on cross-site calls.
  it("POST /api/does-not-exist with cross-site Sec-Fetch-Site → 403 (guard before 404)", async () => {
    const res = await fetch(`${baseUrl}/api/does-not-exist`, {
      method: "POST",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("PATCH /api/does-not-exist with cross-site Sec-Fetch-Site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/does-not-exist`, {
      method: "PATCH",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 403);
  });

  it("DELETE /api/does-not-exist with cross-site Sec-Fetch-Site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/does-not-exist`, {
      method: "DELETE",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 403);
  });

  it("PATCH /api/oidc/service-providers/unknown cross-site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/unknown`, {
      method: "PATCH",
      headers: { "sec-fetch-site": "cross-site", "content-type": "application/json" },
      body: JSON.stringify({ name: "won't happen" })
    });
    assert.strictEqual(res.status, 403);
  });

  it("DELETE /api/saml/service-providers/unknown cross-site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/unknown`, {
      method: "DELETE",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 403);
  });
});

describe("Unknown /api/* GET returns JSON 404, never HTML, never SPA", () => {
  it("GET /api/nope → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/nope`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /API route not found/i);
  });

  it("GET /api/oidc/nope → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/nope`);
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /API route not found/i);
  });

  it("GET /api/saml/nope → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/nope`);
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /API route not found/i);
  });

  it("POST /api/oidc/nope same-origin → 404 JSON (guard OK, endpoint absent)", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/nope`, {
      method: "POST",
      headers: { "sec-fetch-site": "same-origin" }
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /API route not found/i);
  });

  it("No /api/* response leaks the Vite SPA index", async () => {
    for (const path of ["/api/nope", "/api/oidc/nope", "/api/saml/nope"]) {
      const res = await fetch(`${baseUrl}${path}`);
      const body = await res.text();
      assert.doesNotMatch(body, /<div id="root"><\/div>/);
    }
  });
});

describe("Callbacks are NOT routed through the API router", () => {
  it("GET /oidc/callback goes to the callback handler (never through /api/*)", async () => {
    const res = await fetch(`${baseUrl}/oidc/callback?state=nope&code=nope`, {
      redirect: "manual",
      headers: { "sec-fetch-site": "cross-site" }
    });
    // The API guard is NOT applied here (callbacks are outside /api/).
    // The callback handler responds 404 JSON because no running flow matches.
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /No running flow/i);
    assert.doesNotMatch(String(body.error || ""), /Cross-site/i);
  });

  it("POST /saml/acs/:spId goes to the ACS handler (never through /api/*)", async () => {
    const res = await fetch(`${baseUrl}/saml/acs/does-not-exist`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "sec-fetch-site": "cross-site"
      },
      body: "SAMLResponse=&RelayState="
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    // Callback response, not the "Cross-site API request rejected." from the
    // guard.
    assert.doesNotMatch(String(body.error || ""), /Cross-site/i);
  });
});

describe("OIDC and SAML sub-routers stay in their own namespace", () => {
  it("GET /api/oidc/service-providers responds 200 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
  });

  it("GET /api/saml/service-providers responds 200 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
  });

  it("GET /api/oidc/environments responds 200 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/environments`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
  });

  it("No SPA leak from any of these endpoints", async () => {
    for (const path of [
      "/api/oidc/service-providers",
      "/api/saml/service-providers",
      "/api/oidc/environments",
      "/api/oidc/flows",
      "/api/saml/flows"
    ]) {
      const res = await fetch(`${baseUrl}${path}`);
      const body = await res.text();
      assert.doesNotMatch(body, /<div id="root"><\/div>/);
    }
  });
});
