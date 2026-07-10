/**
 * JSON action API contract tests.
 *
 * Boots a real server (child process) on a random port with a temp STORAGE_DIR,
 * then verifies the POST /api endpoints that Vite uses to start / rerun flows:
 *   - unknown SP → 404 JSON
 *   - unknown flow → 404 JSON
 *   - responses never expose client_secret / code_verifier / cleartext state
 *   - SSR start/rerun routes stay reachable
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-actions-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "actions-test-secret-not-real",
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

function assertNoSensitiveFields(body) {
  const serialized = JSON.stringify(body || {});
  assert.ok(!/"client_secret"\s*:/i.test(serialized), "must not expose client_secret");
  assert.ok(!/"code_verifier"\s*:/i.test(serialized), "must not expose code_verifier");
  assert.ok(!/"codeVerifier"\s*:/i.test(serialized), "must not expose codeVerifier");
  assert.ok(!/"expectedState"\s*:/i.test(serialized), "must not expose expectedState");
  assert.ok(!/"expectedNonce"\s*:/i.test(serialized), "must not expose expectedNonce");
  assert.ok(!/"SESSION_SECRET"\s*:/i.test(serialized), "must not expose SESSION_SECRET");
  assert.ok(!/"encryptionKey"\s*:/i.test(serialized), "must not expose encryptionKey");
  assert.ok(!/"sessionSigningKey"\s*:/i.test(serialized), "must not expose sessionSigningKey");
  assert.ok(!/"RelayState"\s*:/i.test(serialized), "must not expose raw RelayState");
}

describe("POST /api/oidc/flows/start/:spId (unknown SP)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/nope-sp`, {
      method: "POST",
      redirect: "manual"
    });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(typeof body.error === "string" && body.error.length > 0);
    assertNoSensitiveFields(body);
  });
});

describe("POST /api/oidc/flows/:id/rerun (unknown flow)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/does-not-exist/rerun`, {
      method: "POST",
      redirect: "manual"
    });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /flow not found/i);
    assertNoSensitiveFields(body);
  });
});

describe("POST /api/saml/flows/start/:spId (unknown SP)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/start/nope-sp`, {
      method: "POST",
      redirect: "manual"
    });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /SAML Service Provider not found/i);
    assertNoSensitiveFields(body);
  });
});

describe("POST /api/saml/flows/:id/rerun (unknown flow)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/does-not-exist/rerun`, {
      method: "POST",
      redirect: "manual"
    });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /SAML flow not found/i);
    assertNoSensitiveFields(body);
  });
});

describe("Action endpoints reject non-POST", () => {
  it("GET /api/oidc/flows/start/:spId returns JSON 404 (route not matched)", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/whatever`);
    // GET matches nothing in /api/*, so the API's own JSON 404 answers.
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /api/oidc/flows/:id/rerun returns JSON 404", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/xxx/rerun`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /api/saml/flows/start/:spId returns JSON 404", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/start/whatever`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /api/saml/flows/:id/rerun returns JSON 404", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/xxx/rerun`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });
});

describe("Backend flow-start routes remain reachable; POST rerun is retired", () => {
  it("GET /oidc/flows/start/unknown redirects (backend redirect, not JSON)", async () => {
    const res = await fetch(`${baseUrl}/oidc/flows/start/unknown-sp`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/oidc\/service-providers/);
  });

  it("POST /oidc/flows/unknown/rerun is retired → 410 JSON", async () => {
    const res = await fetch(`${baseUrl}/oidc/flows/unknown/rerun`, { method: "POST" });
    assert.strictEqual(res.status, 410);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /saml/flows/start/unknown redirects via the backend", async () => {
    const res = await fetch(`${baseUrl}/saml/flows/start/unknown-sp`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/saml\/service-providers/);
  });
});
