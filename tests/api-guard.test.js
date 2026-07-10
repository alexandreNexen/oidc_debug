/**
 * Cross-site guard tests for POST /api/*.
 *
 * The guard rejects browser-driven cross-site POSTs based on Sec-Fetch-Site,
 * with an Origin header fallback for older browsers. Tests / curl calls that
 * send neither header still work (same-origin operational tooling).
 *
 * Also verifies that:
 *   - callbacks (/oidc/callback, /saml/acs/:spId) are not affected;
 *   - SSR POST routes for start/rerun are not affected.
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-guard-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "guard-test-secret-not-real",
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

const ACTION_ENDPOINTS = [
  "/api/oidc/flows/start/unknown-sp",
  "/api/oidc/flows/unknown-flow/rerun",
  "/api/saml/flows/start/unknown-sp",
  "/api/saml/flows/unknown-flow/rerun"
];

describe("Sec-Fetch-Site: cross-site is rejected on every POST /api/* action", () => {
  for (const path of ACTION_ENDPOINTS) {
    it(`POST ${path} with Sec-Fetch-Site: cross-site → 403 JSON`, async () => {
      const res = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { "sec-fetch-site": "cross-site" },
        redirect: "manual"
      });
      assert.strictEqual(res.status, 403);
      assert.match(res.headers.get("content-type") || "", /application\/json/);
      const body = await res.json();
      assert.strictEqual(body.error, "Cross-site API request rejected.");
    });
  }
});

describe("Sec-Fetch-Site: same-origin is accepted (falls through to endpoint logic)", () => {
  it("POST /api/oidc/flows/start/unknown-sp with Sec-Fetch-Site: same-origin → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/unknown-sp`, {
      method: "POST",
      headers: { "sec-fetch-site": "same-origin" }
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
  });

  it("POST /api/saml/flows/unknown-flow/rerun with Sec-Fetch-Site: same-site → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/unknown-flow/rerun`, {
      method: "POST",
      headers: { "sec-fetch-site": "same-site" }
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /SAML flow not found/i);
  });

  it("POST /api/oidc/flows/start/unknown-sp with Sec-Fetch-Site: none → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/unknown-sp`, {
      method: "POST",
      headers: { "sec-fetch-site": "none" }
    });
    assert.strictEqual(res.status, 404);
  });
});

describe("Origin fallback (older browsers, no Sec-Fetch-Site)", () => {
  it("POST /api/oidc/flows/start/unknown-sp with cross-site Origin → 403 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/unknown-sp`, {
      method: "POST",
      headers: { origin: "https://evil.example" }
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("POST /api/saml/flows/start/unknown-sp with cross-site Origin → 403 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/start/unknown-sp`, {
      method: "POST",
      headers: { origin: "https://evil.example" }
    });
    assert.strictEqual(res.status, 403);
  });

  it("POST /api/oidc/flows/unknown-flow/rerun with cross-site Origin → 403 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/unknown-flow/rerun`, {
      method: "POST",
      headers: { origin: "https://evil.example" }
    });
    assert.strictEqual(res.status, 403);
  });

  it("POST /api/saml/flows/unknown-flow/rerun with cross-site Origin → 403 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/saml/flows/unknown-flow/rerun`, {
      method: "POST",
      headers: { origin: "https://evil.example" }
    });
    assert.strictEqual(res.status, 403);
  });

  it("POST with same-origin Origin header → falls through (404 for unknown SP)", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/unknown-sp`, {
      method: "POST",
      headers: { origin: baseUrl }
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
  });

  it("POST with malformed Origin → 403 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/unknown-sp`, {
      method: "POST",
      headers: { origin: "not-a-url" }
    });
    assert.strictEqual(res.status, 403);
  });
});

describe("POST /api/* without any browser header (curl / server-to-server / tests)", () => {
  it("POST /api/oidc/flows/start/unknown-sp without headers → 404 JSON (pre-guard behavior preserved)", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows/start/unknown-sp`, {
      method: "POST"
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
  });
});

describe("Callbacks and backend redirect routes are outside the guard scope", () => {
  it("GET /oidc/callback still reaches the OIDC callback handler", async () => {
    const res = await fetch(`${baseUrl}/oidc/callback?state=nope&code=nope`, {
      redirect: "manual",
      headers: { "sec-fetch-site": "cross-site", origin: "https://evil.example" }
    });
    // Callback handler returns its own 404 JSON when no matching flow is
    // found — the point here is that the guard did NOT swallow it as 403.
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /No running flow/i);
  });

  it("POST /saml/acs/:spId still reaches the ACS handler", async () => {
    const res = await fetch(`${baseUrl}/saml/acs/nonexistent`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "sec-fetch-site": "cross-site",
        origin: "https://evil.example"
      },
      body: "SAMLResponse=&RelayState="
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.match(String(body.error || ""), /RelayState|SAML/i);
  });

  it("Retired POST /oidc/flows/unknown/rerun answers 410 (not 403 from the API guard)", async () => {
    const res = await fetch(`${baseUrl}/oidc/flows/unknown/rerun`, {
      method: "POST",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 410);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("Backend redirect GET /saml/flows/start/unknown with cross-site header is NOT blocked", async () => {
    const res = await fetch(`${baseUrl}/saml/flows/start/unknown-sp`, {
      headers: { "sec-fetch-site": "cross-site" },
      redirect: "manual"
    });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/saml\/service-providers/);
  });
});

describe("GET /api/* is not affected by the guard", () => {
  it("GET /api/oidc/flows with cross-site Sec-Fetch-Site still returns 200 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows`, {
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });
});
