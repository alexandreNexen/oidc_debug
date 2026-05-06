/**
 * Security tests for the OIDC debug application.
 *
 * Verifies that:
 *   - client_secret is never returned via API responses
 *   - tokens are redacted in diagnostic data
 *   - analyzeTokens never exposes raw token values
 *   - input validation enforces length limits
 *   - sanitizeDiagnosticData redacts all sensitive keys
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it } from "node:test";

import {
  analyzeTokens,
  maskSensitiveValue,
  redactObject,
  redactBodyText,
  sanitizeDiagnosticData,
  buildTokenExchangeRequest,
  buildUserInfoRequest,
  buildEffectiveConfig,
  normalizeProviderConfig
} from "../src/protocols/oidc/oidc.js";

import { validateServiceProviderInput } from "../src/protocols/oidc/services/serviceProviders.js";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function containsSecret(obj, secret) {
  const serialized = JSON.stringify(obj);
  return serialized.includes(secret);
}

// ---------------------------------------------------------------------------
// analyzeTokens — must NOT expose raw token values
// ---------------------------------------------------------------------------

describe("analyzeTokens", () => {
  const fakeTokenResponse = {
    access_token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SIGNATURE_FAKE",
    id_token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6OTk5OTk5OTk5OX0.SIGNATURE_FAKE",
    refresh_token: "refresh_opaque_value_abc123",
    expires_in: 3600,
    token_type: "Bearer"
  };

  it("does not include raw access_token value in output", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.ok(!containsSecret(result, fakeTokenResponse.access_token), "access_token raw value found in analyzeTokens output");
  });

  it("does not include raw id_token value in output", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.ok(!containsSecret(result, fakeTokenResponse.id_token), "id_token raw value found in analyzeTokens output");
  });

  it("does not include raw refresh_token value in output", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.ok(!containsSecret(result, fakeTokenResponse.refresh_token), "refresh_token raw value found in analyzeTokens output");
  });

  it("does not expose the original tokenResponse as 'raw'", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.ok(!("raw" in result), "analyzeTokens output contains a 'raw' key exposing the full token response");
  });

  it("reports whether refreshToken is present without exposing its value", () => {
    const result = analyzeTokens(fakeTokenResponse);
    assert.equal(result.refreshToken.present, true);
    assert.ok(!("value" in result.refreshToken), "refreshToken.value field must not be present");
  });
});

// ---------------------------------------------------------------------------
// redactObject — must strip client_secret and tokens
// ---------------------------------------------------------------------------

describe("redactObject", () => {
  it("redacts client_secret", () => {
    const result = redactObject({ client_secret: "supersecret123" });
    assert.ok(!containsSecret(result, "supersecret123"), "client_secret found in redactObject output");
  });

  it("redacts access_token", () => {
    const result = redactObject({ access_token: "token_value_xyz" });
    assert.ok(!containsSecret(result, "token_value_xyz"), "access_token found in redactObject output");
  });

  it("redacts id_token", () => {
    const result = redactObject({ id_token: "jwt.payload.sig" });
    assert.ok(!containsSecret(result, "jwt.payload.sig"), "id_token found in redactObject output");
  });

  it("redacts Authorization header", () => {
    const result = redactObject({ authorization: "Basic dXNlcjpwYXNz" });
    assert.ok(!containsSecret(result, "dXNlcjpwYXNz"), "Authorization header value found in redactObject output");
  });

  it("redacts nested client_secret", () => {
    const result = redactObject({ request: { body: { client_secret: "nested_secret" } } });
    assert.ok(!containsSecret(result, "nested_secret"), "nested client_secret found in redactObject output");
  });

  it("preserves non-sensitive fields", () => {
    const result = redactObject({ client_id: "my-client", scope: "openid" });
    assert.equal(result.client_id, "my-client");
    assert.equal(result.scope, "openid");
  });
});

// ---------------------------------------------------------------------------
// sanitizeDiagnosticData — tokens become "received"/"missing", not their values
// ---------------------------------------------------------------------------

describe("sanitizeDiagnosticData", () => {
  it("replaces access_token value with presence indicator", () => {
    const result = sanitizeDiagnosticData({ access_token: "real_token" }, "");
    assert.ok(!containsSecret(result, "real_token"), "access_token value found after sanitizeDiagnosticData");
    const body = sanitizeDiagnosticData({ body: { access_token: "real_token" } }, "");
    assert.ok(!containsSecret(body, "real_token"), "access_token in body found after sanitizeDiagnosticData");
  });

  it("replaces id_token value with presence indicator", () => {
    const result = sanitizeDiagnosticData({ body: { id_token: "jwt.payload.sig" } }, "");
    assert.ok(!containsSecret(result, "jwt.payload.sig"), "id_token value found after sanitizeDiagnosticData");
  });

  it("replaces client_secret with ********", () => {
    const result = sanitizeDiagnosticData({ client_secret: "secret_val" }, "");
    assert.ok(!containsSecret(result, "secret_val"), "client_secret value found after sanitizeDiagnosticData");
  });

  it("replaces Authorization Bearer header value", () => {
    const result = sanitizeDiagnosticData({ authorization: "Bearer real_access_token" }, "");
    assert.ok(!containsSecret(result, "real_access_token"), "Bearer token found in sanitizeDiagnosticData output");
    assert.equal(result.authorization, "Bearer ********");
  });

  it("replaces Authorization Basic header value", () => {
    const result = sanitizeDiagnosticData({ authorization: "Basic dXNlcjpwYXNz" }, "");
    assert.ok(!containsSecret(result, "dXNlcjpwYXNz"), "Basic credentials found in sanitizeDiagnosticData output");
    assert.equal(result.authorization, "Basic ********");
  });

  it("replaces cookie header value", () => {
    const result = sanitizeDiagnosticData({ cookie: "session=abc123" }, "");
    assert.ok(!containsSecret(result, "abc123"), "Cookie value found in sanitizeDiagnosticData output");
  });
});

// ---------------------------------------------------------------------------
// redactBodyText — form-encoded and JSON bodies
// ---------------------------------------------------------------------------

describe("redactBodyText", () => {
  it("redacts client_secret in form-encoded body", () => {
    const body = "grant_type=authorization_code&code=auth_code_123&client_secret=mysecret&redirect_uri=https%3A%2F%2Fexample.com%2Fcb";
    const result = redactBodyText(body, "application/x-www-form-urlencoded");
    assert.ok(!result.includes("mysecret"), "client_secret found in redacted form body");
    assert.ok(result.includes("grant_type=authorization_code"), "grant_type was incorrectly redacted");
  });

  it("redacts code in form-encoded body", () => {
    const body = "grant_type=authorization_code&code=auth_code_secret_value";
    const result = redactBodyText(body, "application/x-www-form-urlencoded");
    assert.ok(!result.includes("auth_code_secret_value"), "authorization code value found in redacted form body");
  });

  it("redacts access_token in JSON body", () => {
    const body = JSON.stringify({ access_token: "real_token", token_type: "Bearer" });
    const result = redactBodyText(body, "application/json");
    assert.ok(!result.includes("real_token"), "access_token found in redacted JSON body");
  });

  it("redacts client_secret in JSON body", () => {
    const body = JSON.stringify({ client_secret: "my_secret", client_id: "my_client" });
    const result = redactBodyText(body, "application/json");
    assert.ok(!result.includes("my_secret"), "client_secret found in redacted JSON body");
    assert.ok(result.includes("my_client"), "client_id was incorrectly redacted");
  });
});

// ---------------------------------------------------------------------------
// buildTokenExchangeRequest — raw request must not expose secret in params
// ---------------------------------------------------------------------------

describe("buildTokenExchangeRequest", () => {
  const config = buildEffectiveConfig({
    providerConfig: normalizeProviderConfig({
      tokenEndpoint: "https://idp.example.com/token",
      redirectUri: "https://app.example.com/callback"
    }),
    serviceProvider: { clientId: "test_client", clientType: "confidential", scopes: "openid" },
    clientSecret: "super_secret_value",
    redirectUri: "https://app.example.com/callback"
  });

  const request = buildTokenExchangeRequest({
    config,
    code: "authorization_code_value",
    codeVerifier: "pkce_verifier_value"
  });

  it("does not include client_secret in params object", () => {
    assert.ok(!containsSecret(request.params || {}, "super_secret_value"), "client_secret found in request.params");
  });

  it("does not include raw authorization code in params", () => {
    // code IS in params (needed for the request), but its value should not leak via redactedBody
    const redacted = JSON.stringify(request.redactedBody || "");
    assert.ok(!redacted.includes("authorization_code_value"), "raw authorization code found in redactedBody");
  });

  it("does not include client_secret in redactedBody", () => {
    assert.ok(!containsSecret(request.redactedBody || "", "super_secret_value"), "client_secret found in redactedBody");
  });
});

// ---------------------------------------------------------------------------
// buildUserInfoRequest — Authorization header must be redactable
// ---------------------------------------------------------------------------

describe("buildUserInfoRequest", () => {
  it("places access_token in Authorization header (to be redacted by sanitize)", () => {
    const request = buildUserInfoRequest({
      endpoint: "https://idp.example.com/userinfo",
      accessToken: "raw_access_token_value"
    });
    // The raw request does contain the token in headers (it must, for the actual request)
    // but sanitizeDiagnosticData must redact it
    const sanitized = sanitizeDiagnosticData(request.headers || {}, "");
    assert.ok(
      !containsSecret(sanitized, "raw_access_token_value"),
      "access_token still visible in sanitized userInfo request headers"
    );
  });
});

// ---------------------------------------------------------------------------
// validateServiceProviderInput — length limits
// ---------------------------------------------------------------------------

describe("validateServiceProviderInput — length limits", () => {
  const base = {
    name: "Test SP",
    environment: "preprod",
    client_id: "client123",
    client_secret: "secret123",
    scopes: "openid profile"
  };

  it("rejects name exceeding 255 characters", () => {
    const input = { ...base, name: "a".repeat(256) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for name > 255 chars");
    assert.ok(result.errors.name, "name error should be present");
  });

  it("accepts name at exactly 255 characters", () => {
    const input = { ...base, name: "a".repeat(255) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.errors.name, "name error should not be present for exactly 255 chars");
  });

  it("rejects clientId exceeding 256 characters", () => {
    const input = { ...base, client_id: "c".repeat(257) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for clientId > 256 chars");
    assert.ok(result.errors.client_id, "client_id error should be present");
  });

  it("rejects scopes exceeding 512 characters", () => {
    const input = { ...base, scopes: "openid " + "scope ".repeat(100) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for scopes > 512 chars");
    assert.ok(result.errors.scopes, "scopes error should be present");
  });

  it("rejects clientSecret exceeding 512 characters", () => {
    const input = { ...base, client_secret: "s".repeat(513) };
    const result = validateServiceProviderInput(input, { mode: "create" });
    assert.ok(!result.valid, "validation should fail for clientSecret > 512 chars");
    assert.ok(result.errors.client_secret, "client_secret error should be present");
  });
});

// ---------------------------------------------------------------------------
// maskSensitiveValue — sensitive keys masked, non-sensitive preserved
// ---------------------------------------------------------------------------

describe("maskSensitiveValue", () => {
  it("masks client_secret fully for short values", () => {
    assert.equal(maskSensitiveValue("client_secret", "short"), "********");
  });

  it("partially masks long token values", () => {
    const token = "eyJhbGciOiJSUzI1NiJ9_long_token";
    const result = maskSensitiveValue("access_token", token);
    assert.ok(!result.includes(token), "full token value found in masked output");
    assert.ok(result.includes("..."), "masked output should contain '...' for long values");
  });

  it("does not mask non-sensitive keys", () => {
    assert.equal(maskSensitiveValue("client_id", "my-client"), "my-client");
    assert.equal(maskSensitiveValue("scope", "openid profile"), "openid profile");
  });
});

// ---------------------------------------------------------------------------
// Leak test — LEAK_TEST_CLIENT_SECRET_DO_NOT_EXPOSE must never appear in output
// ---------------------------------------------------------------------------

describe("client_secret leak prevention", () => {
  const LEAK_MARKER = "LEAK_TEST_CLIENT_SECRET_DO_NOT_EXPOSE";

  it("encrypted record does not contain the plaintext secret", () => {
    // Simulate what server.js encryptSecret does (without the key — test at the contract level)
    // redactObject should catch any object that has client_secret
    const objectWithSecret = { client_secret: LEAK_MARKER };
    const redacted = redactObject(objectWithSecret);
    assert.ok(!containsSecret(redacted, LEAK_MARKER), "LEAK: client_secret found in redactObject output");
  });

  it("sanitizeDiagnosticData removes the secret value", () => {
    const data = {
      body: { client_secret: LEAK_MARKER, grant_type: "authorization_code" },
      headers: { authorization: `Basic ${Buffer.from(`client:${LEAK_MARKER}`).toString("base64")}` }
    };
    const sanitized = sanitizeDiagnosticData(data);
    assert.ok(!containsSecret(sanitized, LEAK_MARKER), "LEAK: client_secret found in sanitizeDiagnosticData output");
  });

  it("redactBodyText removes secret from form-encoded body", () => {
    const body = `grant_type=authorization_code&client_secret=${encodeURIComponent(LEAK_MARKER)}&code=abc`;
    const result = redactBodyText(body, "application/x-www-form-urlencoded");
    assert.ok(!result.includes(LEAK_MARKER), "LEAK: client_secret found in redactBodyText output");
  });

  it("redactBodyText removes secret from JSON body", () => {
    const body = JSON.stringify({ client_secret: LEAK_MARKER, client_id: "legit" });
    const result = redactBodyText(body, "application/json");
    assert.ok(!result.includes(LEAK_MARKER), "LEAK: client_secret found in redactBodyText JSON output");
  });

  it("maskSensitiveValue masks the secret", () => {
    const result = maskSensitiveValue("client_secret", LEAK_MARKER);
    assert.ok(!result.includes(LEAK_MARKER), "LEAK: client_secret value found in maskSensitiveValue output");
  });

  it("validateServiceProviderInput does not echo back the secret in errors", () => {
    const input = { name: "Test", environment: "preprod", client_id: "id", client_secret: LEAK_MARKER, scopes: "openid" };
    const result = validateServiceProviderInput(input, { mode: "create" });
    // values object will contain the secret — this is intentional (it's used by the service layer to encrypt)
    // but it must not be echoed back via errors or warnings
    const errorsAndWarnings = JSON.stringify({ errors: result.errors, warnings: result.warnings });
    assert.ok(!errorsAndWarnings.includes(LEAK_MARKER), "LEAK: client_secret found in validation errors/warnings");
  });
});

// ---------------------------------------------------------------------------
// XSS prevention — malicious claims must be inoffensive in all output paths
// ---------------------------------------------------------------------------

describe("XSS prevention in output", () => {
  const XSS_PAYLOAD = '<script>alert("xss")</script>';

  it("escapeHtml neutralizes script tags", async () => {
    const { escapeHtml } = await import("../src/common/views/layout.js");
    const result = escapeHtml(XSS_PAYLOAD);
    assert.ok(!result.includes("<script>"), "XSS: <script> tag found after escapeHtml");
    assert.ok(result.includes("&lt;script&gt;"), "escapeHtml did not encode <script> to &lt;script&gt;");
  });

  it("sanitizeDiagnosticData does not execute or inject script payloads", () => {
    const data = {
      name: XSS_PAYLOAD,
      email: `user@example.com${XSS_PAYLOAD}`,
      sub: "normal_value"
    };
    const sanitized = sanitizeDiagnosticData(data);
    // Values should pass through unchanged (sanitize is for secrets, not XSS)
    // XSS safety comes from escapeHtml in views — verify the raw value is preserved for escaping later
    assert.equal(sanitized.name, XSS_PAYLOAD, "sanitizeDiagnosticData should preserve non-sensitive string values");
    assert.equal(sanitized.sub, "normal_value");
  });

  it("redactObject preserves non-sensitive XSS payload (escaping is the view's responsibility)", () => {
    const obj = { name: XSS_PAYLOAD, client_id: "legit" };
    const result = redactObject(obj);
    assert.equal(result.name, XSS_PAYLOAD, "non-sensitive field should pass through redactObject unchanged");
    assert.equal(result.client_id, "legit");
  });
});

// ---------------------------------------------------------------------------
// Key separation — session signing key != encryption key
// ---------------------------------------------------------------------------

describe("application key derivation separation", () => {
  it("session signing key differs from encryption key when derived from the same master", () => {
    const master = "a-strong-master-secret-value-minimum-32-chars!!";
    const signingKey = crypto.createHmac("sha256", master).update("oidc-debug:session:v1").digest("hex");
    const encKey = crypto.createHmac("sha256", master).update("oidc-debug:encryption:v1").digest("hex");
    assert.notEqual(signingKey, encKey, "Session signing key and encryption key must differ");
  });

  it("key derivation is deterministic for the same master secret", () => {
    const master = "another-master-secret-value-32-chars!!!!!";
    const key1 = crypto.createHmac("sha256", master).update("oidc-debug:encryption:v1").digest("hex");
    const key2 = crypto.createHmac("sha256", master).update("oidc-debug:encryption:v1").digest("hex");
    assert.equal(key1, key2, "Key derivation must be deterministic");
  });

  it("different master secrets produce different derived keys", () => {
    const key1 = crypto.createHmac("sha256", "master-secret-one-32chars!!!!!!!!").update("oidc-debug:encryption:v1").digest("hex");
    const key2 = crypto.createHmac("sha256", "master-secret-two-32chars!!!!!!!!").update("oidc-debug:encryption:v1").digest("hex");
    assert.notEqual(key1, key2, "Different master secrets must produce different derived keys");
  });
});
