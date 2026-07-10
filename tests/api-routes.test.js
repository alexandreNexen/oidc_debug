/**
 * Read-only JSON API contract tests.
 *
 * Boots a real server (child process) on a random port with a temp
 * STORAGE_DIR, then verifies:
 *   - /api/* endpoints respond with JSON
 *   - list endpoints never expose secrets or raw tokens
 *   - unknown flow IDs return 404 JSON
 *   - SSR routes still respond with HTML
 *   - callback routes are not shadowed by the API
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-api-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "api-test-secret-not-real",
      LOG_LEVEL: "error",
      STORAGE_DIR: storageDir,
      NODE_ENV: "test"
    },
    stdio: ["ignore", "ignore", "pipe"]
  });

  await waitForHealth(baseUrl);
});

after(() => {
  if (child) {
    child.kill("SIGTERM");
  }
  if (storageDir) {
    rmSync(storageDir, { recursive: true, force: true });
  }
});

describe("GET /api/health", () => {
  it("responds with JSON payload", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.strictEqual(body.status, "ok");
    assert.ok(typeof body.timestamp === "string" && body.timestamp.length > 0);
    assert.ok(body.counts && body.counts.oidc && body.counts.saml);
    assert.strictEqual(typeof body.counts.oidc.serviceProviders, "number");
    assert.strictEqual(typeof body.counts.saml.serviceProviders, "number");
  });
});

describe("GET /api/oidc/service-providers", () => {
  it("responds with JSON list without secrets", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
    const serialized = JSON.stringify(body);
    assert.ok(!/"client_secret"\s*:/i.test(serialized), "must not include client_secret");
    assert.ok(!/"secretRecord"\s*:/i.test(serialized), "must not include secretRecord");
    assert.ok(!/"ciphertext"\s*:/i.test(serialized), "must not include ciphertext");
  });
});

describe("GET /api/oidc/flows", () => {
  it("responds with JSON list", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
    const serialized = JSON.stringify(body);
    assert.ok(!/"codeVerifier"\s*:/i.test(serialized), "must not expose codeVerifier");
    assert.ok(!/"expectedState"\s*:/i.test(serialized), "must not expose expectedState");
    assert.ok(!/"expectedNonce"\s*:/i.test(serialized), "must not expose expectedNonce");
  });
});

describe("GET /api/oidc/flows/:id (unknown)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/does-not-exist`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(typeof body.error === "string" && body.error.length > 0);
  });
});

describe("GET /api/saml/service-providers", () => {
  it("responds with JSON list without secret material", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
    const serialized = JSON.stringify(body);
    assert.ok(!/"privateKey"\s*:/i.test(serialized), "must not include private keys");
    assert.ok(!/"secret"\s*:/i.test(serialized), "must not include a secret field");
  });
});

describe("GET /api/saml/flows", () => {
  it("responds with JSON list", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
  });
});

describe("GET /api/saml/flows/:id (unknown)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/does-not-exist`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(typeof body.error === "string" && body.error.length > 0);
  });
});

describe("Unknown /api/* path", () => {
  it("returns JSON 404 (not HTML)", async () => {
    const res = await fetch(`${baseUrl}/api/does-not-exist`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });
});

describe("Canonical SP list paths now serve the Vite SPA (HTML)", () => {
  it("GET /oidc/service-providers → Vite SPA HTML", async () => {
    const res = await fetch(`${baseUrl}/oidc/service-providers`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<title>Vite frontend — OIDC\/SAML Debug<\/title>/);
  });

  it("GET /saml/service-providers → Vite SPA HTML", async () => {
    const res = await fetch(`${baseUrl}/saml/service-providers`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<div id="root"><\/div>/);
  });
});

describe("Callback routes are NOT shadowed by /api/*", () => {
  it("GET /oidc/callback still reaches the OIDC callback handler", async () => {
    const res = await fetch(`${baseUrl}/oidc/callback?state=nope&code=nope`, { redirect: "manual" });
    // Backend returns 404 JSON when no matching running flow is found —
    // what matters is that this is the backend's 404, not the /api/* JSON 404.
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /No running flow/i);
  });

  it("POST /saml/acs/:spId still reaches the ACS handler", async () => {
    const res = await fetch(`${baseUrl}/saml/acs/nonexistent`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "SAMLResponse=&RelayState="
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.match(String(body.error || ""), /RelayState|SAML/i);
  });
});
