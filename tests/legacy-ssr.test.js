/**
 * Integration tests for the legacy SSR under /legacy/*.
 *
 * Spawns THREE server child processes on separate ports:
 *   - enabled server:      ENABLE_LEGACY_SSR=1, NODE_ENV=production → /legacy/* alive
 *   - disabled prod server: NODE_ENV=production, no flag → /legacy/* returns 404
 *   - disabled dev server:  NODE_ENV=development, no flag → /legacy/* returns 404
 *
 * The dev-disabled case locks in the post-refactor rule that only
 * ENABLE_LEGACY_SSR=1 activates the legacy SSR — NODE_ENV alone no longer
 * does.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const SERVER_ENTRY = fileURLToPath(new URL("../src/server.js", import.meta.url));

let enabledChild = null;
let enabledBaseUrl = "";
let enabledStorage = "";

let disabledChild = null;
let disabledBaseUrl = "";
let disabledStorage = "";

let devDisabledChild = null;
let devDisabledBaseUrl = "";
let devDisabledStorage = "";

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
  const enabledPort = pickPort();
  enabledBaseUrl = `http://127.0.0.1:${enabledPort}`;
  enabledStorage = mkdtempSync(join(tmpdir(), "oidc-debug-legacy-enabled-"));
  enabledChild = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(enabledPort),
      BASE_URL: enabledBaseUrl,
      SESSION_SECRET: "legacy-enabled-secret-not-real",
      LOG_LEVEL: "error",
      STORAGE_DIR: enabledStorage,
      NODE_ENV: "production",
      ENABLE_LEGACY_SSR: "1"
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  await waitForHealth(enabledBaseUrl);

  const disabledPort = pickPort();
  disabledBaseUrl = `http://127.0.0.1:${disabledPort}`;
  disabledStorage = mkdtempSync(join(tmpdir(), "oidc-debug-legacy-disabled-"));
  disabledChild = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(disabledPort),
      BASE_URL: disabledBaseUrl,
      SESSION_SECRET: "legacy-disabled-secret-not-real",
      LOG_LEVEL: "error",
      STORAGE_DIR: disabledStorage,
      NODE_ENV: "production"
      // no ENABLE_LEGACY_SSR
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  await waitForHealth(disabledBaseUrl);

  // A development-mode server without the flag must ALSO have legacy off:
  // this locks in the post-refactor rule that only ENABLE_LEGACY_SSR=1
  // activates it, dev is not enough.
  const devPort = pickPort();
  devDisabledBaseUrl = `http://127.0.0.1:${devPort}`;
  devDisabledStorage = mkdtempSync(join(tmpdir(), "oidc-debug-legacy-dev-disabled-"));
  devDisabledChild = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(devPort),
      BASE_URL: devDisabledBaseUrl,
      SESSION_SECRET: "legacy-dev-disabled-secret-not-real",
      LOG_LEVEL: "error",
      STORAGE_DIR: devDisabledStorage,
      NODE_ENV: "development"
      // no ENABLE_LEGACY_SSR — must NOT activate legacy
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  await waitForHealth(devDisabledBaseUrl);
});

after(() => {
  if (enabledChild) enabledChild.kill("SIGTERM");
  if (disabledChild) disabledChild.kill("SIGTERM");
  if (devDisabledChild) devDisabledChild.kill("SIGTERM");
  if (enabledStorage) rmSync(enabledStorage, { recursive: true, force: true });
  if (disabledStorage) rmSync(disabledStorage, { recursive: true, force: true });
  if (devDisabledStorage) rmSync(devDisabledStorage, { recursive: true, force: true });
});

describe("With ENABLE_LEGACY_SSR=1 the legacy SSR pages are served", () => {
  const readOnlyRoutes = [
    "/legacy",
    "/legacy/",
    "/legacy/oidc/service-providers",
    "/legacy/oidc/service-providers/new",
    "/legacy/saml/service-providers",
    "/legacy/saml/service-providers/new"
  ];

  for (const route of readOnlyRoutes) {
    it(`GET ${route} → SSR HTML`, async () => {
      const res = await fetch(`${enabledBaseUrl}${route}`);
      assert.strictEqual(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /text\/html/);
      const body = await res.text();
      // SSR pages carry the legacy topbar with /legacy/... nav links.
      assert.match(body, /\/legacy\/oidc\/service-providers|\/legacy\/saml\/service-providers/);
    });
  }

  it("GET /legacy/oidc/service-providers/unknown-id/edit → redirects to /legacy list (SP not found)", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/oidc/service-providers/unknown-id/edit`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /^\/legacy\/oidc\/service-providers$/);
  });

  it("GET /legacy/saml/service-providers/unknown-id/edit → redirects to /legacy list", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/saml/service-providers/unknown-id/edit`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /^\/legacy\/saml\/service-providers$/);
  });

  it("GET /legacy/oidc/flows/unknown-id → redirects to /legacy list (flow not found)", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/oidc/flows/unknown-id`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /^\/legacy\/oidc\/service-providers$/);
  });

  it("GET /legacy/saml/flows/unknown-id/details → redirects to /legacy list", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/saml/flows/unknown-id/details`, { redirect: "manual" });
    assert.strictEqual(res.status, 302);
    assert.match(res.headers.get("location") || "", /^\/legacy\/saml\/service-providers$/);
  });

  it("POST /legacy/oidc/service-providers → 405 (legacy is read-only)", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/oidc/service-providers`, { method: "POST" });
    assert.strictEqual(res.status, 405);
  });

  it("GET /legacy/does-not-exist → 404 JSON (no catch-all inside /legacy)", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/does-not-exist`);
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });
});

describe("Legacy assets under /legacy/assets/* are served when enabled", () => {
  it("GET /legacy/assets/app.css → text/css", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/assets/app.css`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /text\/css/);
  });

  it("GET /legacy/assets/app.js → application/javascript", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/assets/app.js`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/javascript/);
  });

  it("GET /legacy/assets/brand/logo.svg → image/svg+xml", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/assets/brand/logo.svg`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /image\/svg\+xml/);
  });

  it("GET /legacy/assets/icons/edit.svg → image/svg+xml", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/assets/icons/edit.svg`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /image\/svg\+xml/);
  });

  it("rejects path traversal under /legacy/assets/", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/assets/..%2F..%2Fpackage.json`);
    assert.strictEqual(res.status, 404);
  });

  it("rejects non-portable characters under /legacy/assets/", async () => {
    const res = await fetch(`${enabledBaseUrl}/legacy/assets/%00malicious`);
    assert.strictEqual(res.status, 404);
  });
});

describe("Without the flag (production default) /legacy/* is disabled", () => {
  const paths = [
    "/legacy",
    "/legacy/",
    "/legacy/oidc/service-providers",
    "/legacy/saml/service-providers",
    "/legacy/assets/app.css",
    "/legacy/assets/icons/edit.svg"
  ];

  for (const path of paths) {
    it(`GET ${path} → 404 JSON (feature-flagged off in prod)`, async () => {
      const res = await fetch(`${disabledBaseUrl}${path}`);
      assert.strictEqual(res.status, 404);
      assert.match(res.headers.get("content-type") || "", /application\/json/);
      const body = await res.json();
      assert.match(String(body.error || ""), /disabled|not found/i);
    });
  }
});

describe("NODE_ENV=development alone must NOT enable legacy (flag-only policy)", () => {
  const paths = [
    "/legacy",
    "/legacy/",
    "/legacy/oidc/service-providers",
    "/legacy/saml/service-providers",
    "/legacy/assets/app.css"
  ];

  for (const path of paths) {
    it(`GET ${path} → 404 JSON in dev without ENABLE_LEGACY_SSR`, async () => {
      const res = await fetch(`${devDisabledBaseUrl}${path}`);
      assert.strictEqual(res.status, 404);
      assert.match(res.headers.get("content-type") || "", /application\/json/);
    });
  }

  it("GET / still serves the Vite SPA in dev even without the legacy flag", async () => {
    const res = await fetch(`${devDisabledBaseUrl}/`);
    assert.strictEqual(res.status, 200);
    const body = await res.text();
    // Either the Vite index (if built) or the "build missing" fallback.
    // Never a legacy SSR dashboard.
    assert.doesNotMatch(body, /\/legacy\/oidc\/service-providers/);
  });
});

describe("Even with legacy enabled the callbacks and /api/* remain untouched", () => {
  it("GET /oidc/callback stays backend (not shadowed by /legacy)", async () => {
    const res = await fetch(`${enabledBaseUrl}/oidc/callback?state=nope&code=nope`, { redirect: "manual" });
    assert.strictEqual(res.status, 404);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const body = await res.json();
    assert.match(String(body.error || ""), /No running flow/i);
  });

  it("POST /saml/acs/nonexistent stays backend", async () => {
    const res = await fetch(`${enabledBaseUrl}/saml/acs/nonexistent`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "SAMLResponse=&RelayState="
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET /api/health returns JSON", async () => {
    const res = await fetch(`${enabledBaseUrl}/api/health`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
  });

  it("GET / still serves the Vite SPA (not the legacy dashboard) even when legacy is enabled", async () => {
    const res = await fetch(`${enabledBaseUrl}/`);
    assert.strictEqual(res.status, 200);
    const body = await res.text();
    assert.match(body, /<title>Vite frontend — OIDC\/SAML Debug<\/title>/);
  });
});
