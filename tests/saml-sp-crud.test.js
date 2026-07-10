/**
 * SAML Service Provider write endpoints (GET :id / POST / PATCH :id / DELETE :id).
 *
 * Verifies:
 *   - creation returns { id, redirectUrl, warnings } with no private key / secret;
 *   - detail GET returns the sanitized SP (with acsUrl) and no secret material;
 *   - unknown id → 404 JSON on GET, PATCH, DELETE;
 *   - validation errors return 400 with fieldErrors;
 *   - PATCH updates fields; secret material never appears;
 *   - DELETE removes the SP; second DELETE returns 404;
 *   - Cross-site guard rejects POST/PATCH/DELETE with 403 JSON;
 *   - SSR routes for new/edit/delete/start remain functional;
 *   - /saml/acs/:spId still reaches the backend ACS handler.
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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-saml-sp-crud-test-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "saml-sp-crud-test-secret-not-real",
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
  assert.ok(!/"privateKey"\s*:/i.test(serialized), "must not expose privateKey");
  assert.ok(!/"secretRecord"\s*:/i.test(serialized), "must not expose secretRecord");
  assert.ok(!/"ciphertext"\s*:/i.test(serialized), "must not expose ciphertext");
  assert.ok(!/"iv"\s*:/i.test(serialized), "must not expose iv");
  assert.ok(!/"tag"\s*:/i.test(serialized), "must not expose tag");
  assert.ok(!/"encryptionKey"\s*:/i.test(serialized), "must not expose encryptionKey");
  assert.ok(!/"sessionSigningKey"\s*:/i.test(serialized), "must not expose sessionSigningKey");
  assert.ok(!/"SESSION_SECRET"\s*:/i.test(serialized), "must not expose SESSION_SECRET");
  assert.ok(!/data\/state\.json/i.test(serialized), "must not leak data/state.json paths");
}

const VALID_PAYLOAD = {
  name: "Alpha SAML SP",
  environment: "preprod",
  spEntityId: "urn:example:sp:alpha",
  idpMetadataMode: "url",
  idpMetadataUrl: "https://idp.example.com/metadata"
};

let createdSpId = "";

describe("POST /api/saml/service-providers", () => {
  it("400 JSON with fieldErrors on empty payload", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({})
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(typeof body.error === "string" && body.error.length > 0);
    assert.ok(body.fieldErrors && typeof body.fieldErrors === "object");
    assert.ok(body.fieldErrors.name || body.fieldErrors.environment || body.fieldErrors.spEntityId);
    assertNoSecretMaterial(body);
  });

  it("400 JSON when spEntityId is missing", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", environment: "preprod" })
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.ok(body.fieldErrors && body.fieldErrors.spEntityId);
  });

  it("creates the SAML SP and returns { id, redirectUrl }", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(VALID_PAYLOAD)
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(typeof body.id === "string" && body.id.startsWith("saml_sp_"));
    assert.strictEqual(body.redirectUrl, "/saml/service-providers");
    assertNoSecretMaterial(body);
    createdSpId = body.id;
  });
});

describe("GET /api/saml/service-providers/:id", () => {
  it("returns the sanitized SP with acsUrl and no secret material", async () => {
    assert.ok(createdSpId, "SP must have been created earlier");
    const res = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(createdSpId)}`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(body.serviceProvider);
    assert.strictEqual(body.serviceProvider.id, createdSpId);
    assert.strictEqual(body.serviceProvider.name, "Alpha SAML SP");
    assert.strictEqual(body.serviceProvider.environment, "preprod");
    assert.strictEqual(body.serviceProvider.spEntityId, "urn:example:sp:alpha");
    assert.strictEqual(body.serviceProvider.idpMetadataUrl, "https://idp.example.com/metadata");
    assert.ok(String(body.serviceProvider.acsUrl || "").endsWith(`/saml/acs/${createdSpId}`));
    assertNoSecretMaterial(body);
  });

  it("returns 404 JSON for an unknown id", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/does-not-exist`);
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /SAML Service Provider not found/i);
  });
});

describe("PATCH /api/saml/service-providers/:id", () => {
  it("returns 404 JSON for an unknown id", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/does-not-exist`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(VALID_PAYLOAD)
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /SAML Service Provider not found/i);
  });

  it("returns 400 with fieldErrors on invalid payload", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "", environment: "", spEntityId: "" })
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.ok(body.fieldErrors && body.fieldErrors.name);
  });

  it("updates fields and returns { id, redirectUrl }", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Alpha SAML SP Renamed",
        environment: "preprod",
        spEntityId: "urn:example:sp:alpha-v2",
        idpMetadataMode: "xml",
        idpMetadataXml: "<EntityDescriptor entityID=\"urn:example:idp\" />"
      })
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.id, createdSpId);
    assert.strictEqual(body.redirectUrl, "/saml/service-providers");
    assertNoSecretMaterial(body);

    const detailRes = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(createdSpId)}`);
    const detail = await detailRes.json();
    assert.strictEqual(detail.serviceProvider.name, "Alpha SAML SP Renamed");
    assert.strictEqual(detail.serviceProvider.spEntityId, "urn:example:sp:alpha-v2");
    assert.strictEqual(detail.serviceProvider.idpMetadataUrl, "");
    assert.match(detail.serviceProvider.idpMetadataXml || "", /EntityDescriptor/);
    assertNoSecretMaterial(detail);
  });
});

describe("DELETE /api/saml/service-providers/:id", () => {
  it("returns 404 JSON for an unknown id", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/does-not-exist`, {
      method: "DELETE"
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(String(body.error || ""), /SAML Service Provider not found/i);
  });

  it("returns 200 JSON on success and the SP disappears", async () => {
    const createRes = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...VALID_PAYLOAD, name: "Bravo to delete", spEntityId: "urn:example:sp:bravo" })
    });
    const created = await createRes.json();
    const id = created.id;

    const delRes = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(delRes.status, 200);
    const body = await delRes.json();
    assert.strictEqual(body.deleted, true);
    assert.strictEqual(body.id, id);
    assert.strictEqual(body.redirectUrl, "/saml/service-providers");
    assertNoSecretMaterial(body);

    const getRes = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(getRes.status, 404);
  });

  it("second DELETE returns 404 (idempotency)", async () => {
    const createRes = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...VALID_PAYLOAD, name: "Charlie to delete", spEntityId: "urn:example:sp:charlie" })
    });
    const { id } = await createRes.json();
    const first = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(first.status, 200);
    const second = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
    assert.strictEqual(second.status, 404);
  });
});

describe("Cross-site guard covers SAML SP write endpoints", () => {
  it("POST cross-site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json", "sec-fetch-site": "cross-site" },
      body: JSON.stringify(VALID_PAYLOAD)
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("PATCH cross-site → 403", async () => {
    const res = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(createdSpId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", "sec-fetch-site": "cross-site" },
      body: JSON.stringify(VALID_PAYLOAD)
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("DELETE cross-site → 403 and SP remains", async () => {
    const createRes = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...VALID_PAYLOAD, name: "Delta guarded", spEntityId: "urn:example:sp:delta" })
    });
    const { id } = await createRes.json();
    const res = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { "sec-fetch-site": "cross-site" }
    });
    assert.strictEqual(res.status, 403);

    const getRes = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(getRes.status, 200);
  });

  it("DELETE with cross-site Origin → 403", async () => {
    const createRes = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...VALID_PAYLOAD, name: "Echo guarded", spEntityId: "urn:example:sp:echo" })
    });
    const { id } = await createRes.json();
    const res = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { origin: "https://evil.example" }
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });
});

describe("Canonical SAML SP GET paths now serve the SPA", () => {
  it("GET /saml/service-providers/new → Vite SPA index", async () => {
    const res = await fetch(`${baseUrl}/saml/service-providers/new`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<title>Vite frontend — OIDC\/SAML Debug<\/title>/);
  });

  it("GET /saml/service-providers/:id/edit → Vite SPA index", async () => {
    const res = await fetch(`${baseUrl}/saml/service-providers/${encodeURIComponent(createdSpId)}/edit`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
    const body = await res.text();
    assert.match(body, /<div id="root"><\/div>/);
  });

  it("POST /saml/service-providers/:id/delete is retired → 410 JSON", async () => {
    const createRes = await fetch(`${baseUrl}/api/saml/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...VALID_PAYLOAD, name: "Foxtrot retired delete", spEntityId: "urn:example:sp:foxtrot" })
    });
    const { id } = await createRes.json();
    const res = await fetch(`${baseUrl}/saml/service-providers/${encodeURIComponent(id)}/delete`, {
      method: "POST"
    });
    assert.strictEqual(res.status, 410);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /retired/i);
    // SP must still exist — the retired POST must not delete it
    const detail = await fetch(`${baseUrl}/api/saml/service-providers/${encodeURIComponent(id)}`);
    assert.strictEqual(detail.status, 200);
  });
});

describe("Callback and start flow paths are untouched", () => {
  it("POST /saml/acs/:spId still reaches the backend ACS handler (400 for empty SAMLResponse)", async () => {
    const res = await fetch(`${baseUrl}/saml/acs/${encodeURIComponent(createdSpId)}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "SAMLResponse=&RelayState="
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.match(String(body.error || ""), /RelayState|SAML/i);
  });

  it("GET /saml/flows/start/unknown-sp still redirects via the backend", async () => {
    const res = await fetch(`${baseUrl}/saml/flows/start/unknown-sp`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/saml\/service-providers/);
  });
});
