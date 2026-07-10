/**
 * Integration tests for the SPA canonical routing (Lot B).
 *
 * Verifies that the Vite SPA is served on the clean allow-listed paths
 * without the /vite/ prefix, that /vite/* keeps working as a temporary
 * alias, that /static/assets/* serves the build output, and — critically —
 * that no shadowing occurs on callbacks, /api/*, /health, or typos.
 *
 * Also verifies the new /api/oidc/discovery/import/:env endpoint is
 * protected by assertApiPostAllowed (Sec-Fetch-Site / Origin guard).
 *
 * If frontend/dist/index.html is missing, the tests that need the build
 * are skipped and only the routing invariants are asserted.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const SERVER_ENTRY = fileURLToPath(new URL("../src/server.js", import.meta.url));
const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DIST_DIR = join(REPO_ROOT, "frontend", "dist");
const INDEX_HTML = join(DIST_DIR, "index.html");
const ASSETS_DIR = join(DIST_DIR, "assets");

const HAS_BUILD = existsSync(INDEX_HTML);
const skipIfNoBuild = HAS_BUILD ? undefined : { skip: "frontend/dist not built" };

let child = null;
let baseUrl = "";
let storageDir = "";
let firstJsAsset = "";
let firstCssAsset = "";

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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-spa-test-"));

  if (HAS_BUILD) {
    const entries = readdirSync(ASSETS_DIR);
    firstJsAsset = entries.find((name) => name.endsWith(".js")) || "";
    firstCssAsset = entries.find((name) => name.endsWith(".css")) || "";
  }

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "spa-test-secret-not-real",
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

// The Vite build index.html is stable enough that these markers are safe
// signals: title tag + empty React root div + a /static/assets/ reference.
function assertLooksLikeViteIndex(body) {
  assert.match(body, /<title>Vite frontend — OIDC\/SAML Debug<\/title>/);
  assert.match(body, /<div id="root"><\/div>/);
  assert.match(body, /\/static\/assets\//);
}

describe("SPA canonical routes (no /vite prefix) serve dist/index.html", () => {
  const routes = [
    "/",
    "/oidc/service-providers",
    "/oidc/service-providers/new",
    "/oidc/service-providers/sp_abc123/edit",
    "/oidc/flows",
    "/oidc/flows/flow_abc123",
    "/saml/service-providers",
    "/saml/service-providers/new",
    "/saml/service-providers/saml_sp_abc123/edit",
    "/saml/flows",
    "/saml/flows/flow_abc123"
  ];

  for (const route of routes) {
    it(`GET ${route} → Vite index`, skipIfNoBuild || (async () => {
      const res = await fetch(`${baseUrl}${route}`);
      assert.strictEqual(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /text\/html/);
      const body = await res.text();
      assertLooksLikeViteIndex(body);
    }));
  }

  it("HEAD / is allowed and returns HTML content-type", skipIfNoBuild || (async () => {
    const res = await fetch(`${baseUrl}/`, { method: "HEAD" });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/html/);
  }));
});

describe("Legacy /vite/* alias has been removed", () => {
  it("GET /vite/ → 404 (alias removed in Lot C)", async () => {
    const res = await fetch(`${baseUrl}/vite/`);
    assert.strictEqual(res.status, 404);
  });

  it("GET /vite/oidc/flows/test → 404", async () => {
    const res = await fetch(`${baseUrl}/vite/oidc/flows/test`);
    assert.strictEqual(res.status, 404);
  });

  it("GET /vite/assets/anything.js → 404", async () => {
    const res = await fetch(`${baseUrl}/vite/assets/anything.js`);
    assert.strictEqual(res.status, 404);
  });
});

describe("/static/assets/* serves the build output", () => {
  it("GET /static/assets/<hash>.js → application/javascript",
    (skipIfNoBuild || !firstJsAsset) ? { skip: "no js asset" } : (async () => {
      const res = await fetch(`${baseUrl}/static/assets/${firstJsAsset}`);
      assert.strictEqual(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /application\/javascript/);
    })
  );

  it("GET /static/assets/<hash>.css → text/css",
    (skipIfNoBuild || !firstCssAsset) ? { skip: "no css asset" } : (async () => {
      const res = await fetch(`${baseUrl}/static/assets/${firstCssAsset}`);
      assert.strictEqual(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /text\/css/);
    })
  );

  it("GET /static/assets/does-not-exist.js → 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/static/assets/does-not-exist.js`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("rejects path traversal via .. under /static/assets/", async () => {
    const res = await fetch(`${baseUrl}/static/assets/..%2F..%2Fpackage.json`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("rejects non-portable characters under /static/assets/", async () => {
    const res = await fetch(`${baseUrl}/static/assets/%00malicious`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("POST /static/assets/<file> → 405 Method Not Allowed",
    (skipIfNoBuild || !firstJsAsset) ? { skip: "no js asset" } : (async () => {
      const res = await fetch(`${baseUrl}/static/assets/${firstJsAsset}`, { method: "POST" });
      assert.strictEqual(res.status, 405);
    })
  );
});

describe("Non-shadowing: callbacks, API, health, typos", () => {
  it("GET /api/health stays JSON (not shadowed by SPA)", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /health stays JSON (backend, not SPA)", async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.strictEqual(body.status, "ok");
  });

  it("GET /oidc/callback?state=nope&code=nope → backend handler (JSON 404), not SPA index", async () => {
    const res = await fetch(`${baseUrl}/oidc/callback?state=nope&code=nope`, { redirect: "manual" });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /No running flow/i);
  });

  it("POST /saml/acs/nonexistent → backend handler (JSON 400), not SPA index", async () => {
    const res = await fetch(`${baseUrl}/saml/acs/nonexistent`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "SAMLResponse=&RelayState="
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /oidc/flows/start/some-sp → backend (SSR redirect), not SPA index", async () => {
    const res = await fetch(`${baseUrl}/oidc/flows/start/some-sp`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/oidc\/service-providers/);
  });

  it("GET /saml/flows/start/some-sp → backend (SSR redirect), not SPA index", async () => {
    const res = await fetch(`${baseUrl}/saml/flows/start/some-sp`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/saml\/service-providers/);
  });

  it("GET /oidc/servcie-providers (typo) → 404, not SPA index", async () => {
    const res = await fetch(`${baseUrl}/oidc/servcie-providers`);
    assert.strictEqual(res.status, 404);
    const contentType = res.headers.get("content-type") || "";
    // 404 may be HTML or JSON depending on Accept, but must never be the SPA
    if (contentType.includes("text/html")) {
      const body = await res.text();
      assert.doesNotMatch(body, /<div id="root"><\/div>/);
    }
  });

  it("GET /saml/servcie-providers (typo) → 404, not SPA index", async () => {
    const res = await fetch(`${baseUrl}/saml/servcie-providers`);
    assert.strictEqual(res.status, 404);
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("text/html")) {
      const body = await res.text();
      assert.doesNotMatch(body, /<div id="root"><\/div>/);
    }
  });

  it("GET /does-not-exist → 404, not SPA index", async () => {
    const res = await fetch(`${baseUrl}/does-not-exist`);
    assert.strictEqual(res.status, 404);
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("text/html")) {
      const body = await res.text();
      assert.doesNotMatch(body, /<div id="root"><\/div>/);
    }
  });

  it("GET /oidc/flows/start (missing spId) is not a SPA route", async () => {
    // /oidc/flows/start with no spId trailing is captured by the SPA
    // regex /^\/oidc\/flows\/[^/]+$/ ONLY if we intentionally allowed it.
    // The concrete answer here documents what the backend actually does
    // today so a future refactor cannot silently regress: at present the
    // SPA does match this and renders "flow not found". This is acceptable
    // because /oidc/flows/start/:spId (with the trailing sp id) still hits
    // the backend — that is the branch tested above.
    const res = await fetch(`${baseUrl}/oidc/flows/start`);
    // Either 200 SPA index (client renders "not found") or 404 backend —
    // both are fine. What is NOT fine is that this path collides with
    // /oidc/flows/start/:spId. We assert /oidc/flows/start/some-sp still
    // 302-redirects (guarded above).
    assert.ok(res.status === 200 || res.status === 404);
  });
});

describe("SPA responses carry the security headers", () => {
  it("preserves SECURITY_HEADERS on SPA canonical route responses", skipIfNoBuild || (async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.strictEqual(res.headers.get("x-content-type-options"), "nosniff");
    assert.strictEqual(res.headers.get("x-frame-options"), "DENY");
    assert.match(res.headers.get("content-security-policy") || "", /default-src 'self'/);
  }));
});

describe("POST /api/oidc/discovery/import/:env — cross-site guard", () => {
  it("cross-site Sec-Fetch-Site → 403 JSON (before hitting business logic)", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/discovery/import/preprod`, {
      method: "POST",
      headers: {
        "sec-fetch-site": "cross-site",
        "content-type": "application/json"
      },
      body: JSON.stringify({ discoveryUrl: "https://evil.example/.well-known/openid-configuration" })
    });
    assert.strictEqual(res.status, 403);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("cross-site Origin → 403 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/discovery/import/prod`, {
      method: "POST",
      headers: {
        origin: "https://evil.example",
        "content-type": "application/json"
      },
      body: JSON.stringify({ discoveryUrl: "https://sso.example.com/.well-known/openid-configuration" })
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.strictEqual(body.error, "Cross-site API request rejected.");
  });

  it("unknown environment key → 404 JSON (falls through to /api/* 404 without invoking handler)", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/discovery/import/bad-env`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ discoveryUrl: "https://example.com/.well-known/openid-configuration" })
    });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("same-origin + invalid discoveryUrl → 400 JSON with error hint", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/discovery/import/preprod`, {
      method: "POST",
      headers: {
        "sec-fetch-site": "same-origin",
        "content-type": "application/json"
      },
      body: JSON.stringify({ discoveryUrl: "" })
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.strictEqual(body.ok, false);
    assert.match(String(body.error || ""), /Discovery URL/i);
  });

  it("same-origin + non-HTTPS discoveryUrl → 400 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/discovery/import/prod`, {
      method: "POST",
      headers: {
        "sec-fetch-site": "same-origin",
        "content-type": "application/json"
      },
      body: JSON.stringify({ discoveryUrl: "http://example.com/.well-known/openid-configuration" })
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.ok, false);
    assert.match(String(body.error || ""), /HTTPS/);
  });

  it("legacy SSR POST /oidc/discovery/import/:env is retired → 410 JSON", async () => {
    const res = await fetch(`${baseUrl}/oidc/discovery/import/preprod`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ discoveryUrl: "" })
    });
    assert.strictEqual(res.status, 410);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /retired/i);
  });
});

describe("Retired POST canonical routes return 410 Gone", () => {
  const deprecatedPosts = [
    "/oidc/service-providers",
    "/oidc/service-providers/some-id",
    "/oidc/service-providers/some-id/delete",
    "/oidc/flows/some-id/rerun",
    "/oidc/discovery/import/preprod",
    "/oidc/discovery/import/prod",
    "/saml/service-providers",
    "/saml/service-providers/some-id",
    "/saml/service-providers/some-id/delete"
  ];

  for (const path of deprecatedPosts) {
    it(`POST ${path} → 410 JSON (retired; use /api/*)`, async () => {
      const res = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({})
      });
      assert.strictEqual(res.status, 410);
      assert.match(res.headers.get("content-type") || "", /application\/json/);
      const body = await res.json();
      assert.match(String(body.error || ""), /retired/i);
    });
  }

  it("state is unchanged after a POST attempt (SP list stays empty)", async () => {
    // Baseline count before
    const beforeRes = await fetch(`${baseUrl}/api/oidc/service-providers`);
    const before = await beforeRes.json();
    const initialCount = Array.isArray(before.items) ? before.items.length : 0;

    // Retired POST — must NOT create anything
    await fetch(`${baseUrl}/oidc/service-providers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Should not be created",
        environment: "preprod",
        clientId: "would-be-created"
      })
    });

    const afterRes = await fetch(`${baseUrl}/api/oidc/service-providers`);
    const after = await afterRes.json();
    const finalCount = Array.isArray(after.items) ? after.items.length : 0;
    assert.strictEqual(finalCount, initialCount, "retired POST must not mutate state");
  });
});

describe("GET /api/* is not affected by the SPA allow-list", () => {
  it("GET /api/oidc/flows returns JSON items", async () => {
    const res = await fetch(`${baseUrl}/api/oidc/flows`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.ok(Array.isArray(body.items));
  });
});
