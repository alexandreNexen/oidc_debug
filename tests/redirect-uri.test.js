/**
 * Canonical redirect URI safety test.
 *
 * Guards the architectural rule: the OIDC redirect_uri MUST be built from the
 * backend's canonical BASE_URL, never from the Vite dev host. Vite's default
 * dev port (5173) and preview port (4173) must never appear in FIXED_REDIRECT_URI.
 *
 * See README.md ("URL canonique et matrice d'usage dev") and
 * frontend/README.md ("URL canonique et rôle du proxy").
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FIXED_REDIRECT_URI } from "../src/protocols/oidc/oidc.js";

describe("FIXED_REDIRECT_URI canonical form", () => {
  it("is a well-formed absolute URL", () => {
    const parsed = new URL(FIXED_REDIRECT_URI);
    assert.ok(parsed.protocol === "http:" || parsed.protocol === "https:", `unexpected protocol: ${parsed.protocol}`);
    assert.ok(parsed.hostname.length > 0, "hostname must not be empty");
  });

  it("ends with the callback path /oidc/callback", () => {
    assert.ok(
      FIXED_REDIRECT_URI.endsWith("/oidc/callback"),
      `expected redirect URI to end with /oidc/callback, got: ${FIXED_REDIRECT_URI}`
    );
  });

  it("does not use the Vite dev port (5173)", () => {
    const parsed = new URL(FIXED_REDIRECT_URI);
    assert.notStrictEqual(
      parsed.port,
      "5173",
      "FIXED_REDIRECT_URI must not point at the Vite dev port; set BASE_URL to the backend's canonical URL"
    );
  });

  it("does not use the Vite preview port (4173)", () => {
    const parsed = new URL(FIXED_REDIRECT_URI);
    assert.notStrictEqual(
      parsed.port,
      "4173",
      "FIXED_REDIRECT_URI must not point at the Vite preview port; set BASE_URL to the backend's canonical URL"
    );
  });
});
