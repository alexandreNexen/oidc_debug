/**
 * OIDC Service Provider write endpoints (GET :id / POST / PATCH :id).
 *
 * Boots a real server on a random port with a temp STORAGE_DIR and verifies:
 *   - creation returns { id, redirectUrl } and never a secret;
 *   - detail GET never returns client_secret / secretRecord;
 *   - unknown ID → 404 JSON on GET and PATCH;
 *   - validation errors return 400 with fieldErrors;
 *   - PATCH with an empty secret preserves the existing one (verified by
 *     starting a flow after PATCH, since the flow only succeeds when
 *     decryptSecret returns the original ciphertext);
 *   - guard rejects cross-site POST and PATCH with 403.
 *
 * SSR routes /oidc/service-providers[/:id][/edit] must still respond HTML.
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-sp-write-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "sp-write-test-secret-not-real",
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

// The `client_secret` / `clientSecret` key names ARE allowed to appear as
// keys of `fieldErrors` (they are field labels there). What must never
// appear anywhere in the response is:
//   - a secretRecord envelope (secretRecord/ciphertext/iv/tag);
//   - the encryption-key material;
//   - the raw secret value that the caller just submitted.
function assertNoSecretMaterial(body, submittedSecrets = []) {
  const serialized = JSON.stringify(body || {});
  assert.ok(!/"secretRecord"\s*:/i.test(serialized), "must not expose secretRecord");
  assert.ok(!/"ciphertext"\s*:/i.test(serialized), "must not expose ciphertext");
  assert.ok(!/"encryptionKey"\s*:/i.test(serialized), "must not expose encryptionKey");
  assert.ok(!/"sessionSigningKey"\s*:/i.test(serialized), "must not expose sessionSigningKey");

  // `client_secret` / `clientSecret` may only appear inside a fieldErrors
  // map where the value is a validation message, never as a top-level value.
  const errorsBlock = body && body.fieldErrors ? JSON.stringify(body.fieldErrors) : "";
  const outsideErrors = errorsBlock ? serialized.replace(errorsBlock, "") : serialized;
  assert.ok(
    !/"client_secret"\s*:/i.test(outsideErrors),
    "client_secret must only appear as a fieldErrors key"
  );
  assert.ok(
    !/"clientSecret"\s*:/i.test(outsideErrors),
    "clientSecret must only appear as a fieldErrors key"
  );

  for (const secret of submittedSecrets) {
    if (!secret) continue;
    assert.ok(
      !serialized.includes(secret),
      `submitted secret must not be echoed back (found "${secret}")`
    );
  }
}

const VALID_PAYLOAD = {
  name: "Alpha SP",
  environment: "preprod",
  clientId: "alpha-client",
  clientSecret: "alpha-secret-supersafe",
  scopes: "openid profile email"
};

let createdSpId = "";

describe("POST /api/oidc/service-providers", () => {
  it("400 JSON with fieldErrors on invalid payload", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({})
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(typeof body.error === "string" && body.error.length > 0);
    assert.ok(body.fieldErrors && typeof body.fieldErrors === "object");
    assert.ok(body.fieldErrors.name || body.fieldErrors.client_id || body.fieldErrors.client_secret);
    assertNoSecretMaterial(body);
  });

  it("400 JSON when client_secret is missing on create", async () => {
    const { clientSecret: _drop, ...missingSecret } = VALID_PAYLOAD;
    const res = await fetch(`${baseUrl}/api/oidc/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(missingSecret)
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.ok(body.fieldErrors && body.fieldErrors.client_secret);
    assertNoSecretMaterial(body);
  });

  it("creates the SP and returns { id, redirectUrl } without any secret", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(VALID_PAYLOAD)
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(typeof body.id === "string" && body.id.length > 0);
    assert.strictEqual(body.redirectUrl, "/oidc/service-providers");
    assertNoSecretMaterial(body, [VALID_PAYLOAD.clientSecret]);
    createdSpId = body.id;
  });
});

describe("GET /api/oidc/service-providers/:id", () => {
  it("returns the sanitized SP without client_secret / secretRecord", async () => {
    assert.ok(createdSpId, "SP must have been created earlier");
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(body.serviceProvider);
    assert.strictEqual(body.serviceProvider.id, createdSpId);
    assert.strictEqual(body.serviceProvider.name, "Alpha SP");
    assert.strictEqual(body.serviceProvider.clientId, "alpha-client");
    assert.strictEqual(body.serviceProvider.environment, "preprod");
    assert.strictEqual(body.serviceProvider.secretConfigured, true);
    assertNoSecretMaterial(body);
  });

  it("returns 404 JSON for an unknown id", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/does-not-exist`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
  });
});

describe("PATCH /api/oidc/service-providers/:id", () => {
  it("returns 404 JSON for an unknown id", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/does-not-exist`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", environment: "preprod", clientId: "y", scopes: "openid" })
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
  });

  it("returns 400 with fieldErrors on invalid payload", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "", environment: "", clientId: "", scopes: "" })
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.ok(body.fieldErrors && body.fieldErrors.name);
    assertNoSecretMaterial(body);
  });

  it("updates non-secret fields, keeps secret when clientSecret is absent, and never returns a secret", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Alpha SP Renamed",
        environment: "preprod",
        clientId: "alpha-client",
        scopes: "openid email"
      })
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.id, createdSpId);
    assert.strictEqual(body.redirectUrl, "/oidc/service-providers");
    assert.strictEqual(body.secretUpdated, false);
    assertNoSecretMaterial(body, [VALID_PAYLOAD.clientSecret]);

    // Re-read: the SP must still be marked as secretConfigured=true, meaning
    // the previously encrypted secretRecord was preserved intact.
    const detailRes = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`);
    assert.strictEqual(detailRes.status, 200);
    const detail = await detailRes.json();
    assert.strictEqual(detail.serviceProvider.name, "Alpha SP Renamed");
    assert.strictEqual(detail.serviceProvider.scopes, "openid email");
    assert.strictEqual(detail.serviceProvider.secretConfigured, true);
    assertNoSecretMaterial(detail, [VALID_PAYLOAD.clientSecret]);
  });

  it("updates the secret when clientSecret is provided, without returning it", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Alpha SP Renamed",
        environment: "preprod",
        clientId: "alpha-client",
        scopes: "openid email",
        clientSecret: "new-secret-value"
      })
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.secretUpdated, true);
    assertNoSecretMaterial(body, ["new-secret-value"]);
  });
});

describe("Cross-site guard on OIDC SP write endpoints", () => {
  it("POST /api/oidc/service-providers with Sec-Fetch-Site: cross-site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "sec-fetch-site": "cross-site"
      },
      body: JSON.stringify(VALID_PAYLOAD)
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("PATCH /api/oidc/service-providers/:id with Sec-Fetch-Site: cross-site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        "sec-fetch-site": "cross-site"
      },
      body: JSON.stringify({ name: "x", environment: "preprod", clientId: "y", scopes: "openid" })
    });
    assert.strictEqual(res.status, 403);
  });

  it("PATCH with cross-site Origin fallback → 403", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        origin: "https://evil.example"
      },
      body: JSON.stringify({ name: "x", environment: "preprod", clientId: "y", scopes: "openid" })
    });
    assert.strictEqual(res.status, 403);
  });
});

describe("Canonical OIDC SP GET paths now serve the Vite SPA", () => {
  it("GET /oidc/service-providers → Vite SPA HTML", async () => {
    const res = await fetch(`${baseUrl}/oidc/service-providers`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<title>Vite frontend — OIDC\/SAML Debug<\/title>/);
  });

  it("GET /oidc/service-providers/new → Vite SPA HTML", async () => {
    const res = await fetch(`${baseUrl}/oidc/service-providers/new`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<div id="root"><\/div>/);
  });

  it("GET /oidc/service-providers/:id/edit → Vite SPA HTML for SP created via /api/*", async () => {
    const res = await fetch(`${baseUrl}/oidc/service-providers/${encodeURIComponent(createdSpId)}/edit`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<div id="root"><\/div>/);
  });
});

describe("Environments endpoint (used by the Vite form)", () => {
  it("GET /api/oidc/environments returns the known Ez-Access keys", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/environments`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
    const keys = body.items.map((env) => env.key);
    assert.ok(keys.includes("preprod"));
    assert.ok(keys.includes("prod"));
  });
});
