/**
 * DELETE /api/oidc/service-providers/:id contract tests.
 *
 * Verifies:
 *   - unknown id → 404 JSON;
 *   - existing id → 200 JSON with { deleted, id, redirectUrl } and no secret
 *     material;
 *   - after delete, GET /api/oidc/service-providers/:id → 404 JSON;
 *   - cross-site DELETE (Sec-Fetch-Site or Origin) → 403 JSON;
 *   - SSR POST /oidc/service-providers/:id/delete still redirects.
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-sp-delete-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "sp-delete-test-secret-not-real",
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

function assertNoSecretMaterial(body) {
  const serialized = JSON.stringify(body || {});
  assert.ok(!/"client_secret"\s*:/i.test(serialized), "must not expose client_secret");
  assert.ok(!/"clientSecret"\s*:/i.test(serialized), "must not expose clientSecret");
  assert.ok(!/"secretRecord"\s*:/i.test(serialized), "must not expose secretRecord");
  assert.ok(!/"ciphertext"\s*:/i.test(serialized), "must not expose ciphertext");
  assert.ok(!/"iv"\s*:/i.test(serialized), "must not expose iv");
  assert.ok(!/"tag"\s*:/i.test(serialized), "must not expose tag");
  assert.ok(!/"encryptionKey"\s*:/i.test(serialized), "must not expose encryptionKey");
  assert.ok(!/"sessionSigningKey"\s*:/i.test(serialized), "must not expose sessionSigningKey");
}

async function createSp(name = "Delete-Me SP", clientId = "delete-me-client") {
  const res = await fetch(`${baseUrl}/api/oidc/service-providers`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name,
      environment: "preprod",
      clientId,
      clientSecret: "temporary-secret-for-delete-test",
      scopes: "openid"
    })
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  return body.id;
}

describe("DELETE /api/oidc/service-providers/:id (unknown)", () => {
  it("returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/does-not-exist`, {
      method: "DELETE"
    });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
    assertNoSecretMaterial(body);
  });
});

describe("DELETE /api/oidc/service-providers/:id (existing)", () => {
  it("returns 200 JSON with { deleted, id, redirectUrl } and no secret", async () => {
    const id = await createSp("Alpha to delete", "alpha-delete");
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.deleted, true);
    assert.strictEqual(body.id, id);
    assert.strictEqual(body.redirectUrl, "/oidc/service-providers");
    assertNoSecretMaterial(body);
  });

  it("after DELETE, GET /api/oidc/service-providers/:id returns 404 JSON", async () => {
    const id = await createSp("Bravo to delete", "bravo-delete");
    const deleteRes = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(deleteRes.status, 200);

    const getRes = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(getRes.status, 404);
    const body = await getRes.json();
    assert.match(String(body.error || ""), /Service Provider not found/i);
  });

  it("second DELETE on the same id returns 404 JSON (idempotency check)", async () => {
    const id = await createSp("Charlie to delete", "charlie-delete");
    const first = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(first.status, 200);

    const second = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(second.status, 404);
  });
});

describe("Cross-site guard covers DELETE", () => {
  it("DELETE with Sec-Fetch-Site: cross-site → 403 JSON", async () => {
    const id = await createSp("Delta to delete", "delta-delete");
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");

    // The SP must still exist since the guard blocked before the handler.
    const getRes = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(getRes.status, 200);
  });

  it("DELETE with cross-site Origin → 403 JSON", async () => {
    const id = await createSp("Echo to delete", "echo-delete");
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { origin: "https://evil.example" }
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");

    const getRes = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(getRes.status, 200);
  });

  it("DELETE with Sec-Fetch-Site: same-origin is allowed", async () => {
    const id = await createSp("Foxtrot to delete", "foxtrot-delete");
    const res = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { "sec-fetch-site": "same-origin" }
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.deleted, true);
  });
});

describe("Retired SSR delete route responds 410 without mutating state", () => {
  it("POST /oidc/service-providers/:id/delete → 410 JSON; SP is NOT deleted", async () => {
    const id = await createSp("Golf pinned to retired POST", "golf-delete");
    const res = await fetch(`${baseUrl}/oidc/service-providers/${encodeURIComponent(id)}/delete`, {
      method: "POST"
    });
    assert.strictEqual(res.status, 410);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /retired/i);

    // SP must still exist (retired POST did not delete it)
    const getRes = await fetch(`${baseUrl}/api/oidc/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(getRes.status, 200);
  });

  it("POST /oidc/service-providers/unknown/delete → 410 JSON (no side effect)", async () => {
    const res = await fetch(`${baseUrl}/oidc/service-providers/unknown-id/delete`, {
      method: "POST"
    });
    assert.strictEqual(res.status, 410);
  });
});
