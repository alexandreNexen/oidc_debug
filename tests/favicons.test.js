/**
 * Integration tests locking in the favicon serving behavior.
 *
 * favicon.ico is binary (MS Windows icon resource); it MUST be served
 * byte-for-byte with Content-Type image/x-icon. Prior to the fix in
 * src/routes/static.js the file was read with `utf8` encoding which
 * corrupted the bytes on the wire.
 *
 * favicon.svg is text (SVG XML) and is served with Content-Type
 * image/svg+xml.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const SERVER_ENTRY = fileURLToPath(new URL("../src/server.js", import.meta.url));
const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const FAVICON_ICO_PATH = join(REPO_ROOT, "public", "assets", "favicon.ico");
const FAVICON_SVG_PATH = join(REPO_ROOT, "public", "assets", "favicon.svg");

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
  storageDir = mkdtempSync(join(tmpdir(), "oidc-debug-favicons-"));

  child = spawn("node", [SERVER_ENTRY], {
    env: {
      ...process.env,
      PORT: String(port),
      BASE_URL: baseUrl,
      SESSION_SECRET: "favicons-test-secret-not-real",
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

describe("GET /favicon.ico serves the binary icon byte-for-byte", () => {
  it("returns 200 with Content-Type image/x-icon", async () => {
    const res = await fetch(`${baseUrl}/favicon.ico`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /^image\/x-icon/);
  });

  it("response body length matches the file on disk", async () => {
    const expected = readFileSync(FAVICON_ICO_PATH);
    const res = await fetch(`${baseUrl}/favicon.ico`);
    const bodyBytes = new Uint8Array(await res.arrayBuffer());
    assert.strictEqual(bodyBytes.length, expected.length,
      `served ${bodyBytes.length} bytes but the file is ${expected.length} bytes`);
  });

  it("response body is byte-for-byte identical to the file on disk", async () => {
    const expected = readFileSync(FAVICON_ICO_PATH);
    const res = await fetch(`${baseUrl}/favicon.ico`);
    const bodyBytes = Buffer.from(await res.arrayBuffer());
    assert.ok(Buffer.compare(bodyBytes, expected) === 0,
      "served bytes differ from the file on disk (encoding corruption?)");
  });

  it("first four bytes are the ICO magic number 00 00 01 00", async () => {
    // MS Windows icon resource header: two little-endian shorts, reserved=0
    // then type=1. This can only be preserved if the transfer is binary.
    const res = await fetch(`${baseUrl}/favicon.ico`);
    const bodyBytes = new Uint8Array(await res.arrayBuffer());
    assert.strictEqual(bodyBytes[0], 0x00);
    assert.strictEqual(bodyBytes[1], 0x00);
    assert.strictEqual(bodyBytes[2], 0x01);
    assert.strictEqual(bodyBytes[3], 0x00);
  });
});

describe("GET /favicon.svg keeps text/SVG semantics", () => {
  it("returns 200 with Content-Type image/svg+xml", async () => {
    const res = await fetch(`${baseUrl}/favicon.svg`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /^image\/svg\+xml/);
  });

  it("body is a valid SVG (starts with <svg or <?xml)", async () => {
    const res = await fetch(`${baseUrl}/favicon.svg`);
    const body = await res.text();
    assert.match(body, /^(?:<\?xml[^?]*\?>\s*)?<svg\b/i);
  });

  it("body length matches the file on disk", async () => {
    const expected = readFileSync(FAVICON_SVG_PATH);
    const res = await fetch(`${baseUrl}/favicon.svg`);
    const bodyBytes = Buffer.from(await res.arrayBuffer());
    assert.strictEqual(bodyBytes.length, expected.length);
  });
});
