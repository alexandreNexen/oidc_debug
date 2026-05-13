import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getEzAccessEnvironment, listEzAccessEnvironments } from "./common/views/config.js";
import {
  decodeJwt,
  buildCurlCommand,
  buildEffectiveConfig,
  buildTokenExchangeRequest,
  buildUserInfoRequest,
  createProviderConfig,
  FIXED_REDIRECT_URI,
  mergeDiscoveryIntoProviderConfig,
  normalizeProviderConfig,
  normalizeServiceProvider,
  prepareAuthorizationRequest,
  redactBodyText,
  redactObject,
  safeJsonParse,
  sanitizeDiagnosticData
} from "./protocols/oidc/oidc.js";
import { createFlowService, STEP_ORDER } from "./protocols/oidc/services/flows.js";
import { createServiceProviderService, isServiceProviderReady, serviceProviderStatus } from "./protocols/oidc/services/serviceProviders.js";
import { renderDashboard } from "./common/views/dashboard.js";
import { renderFlowDetailsPage } from "./protocols/oidc/views/flowDetails.js";
import { renderFlowResultPage } from "./protocols/oidc/views/flowResult.js";
import { renderServiceProvidersPage } from "./protocols/oidc/views/serviceProviders.js";
import { renderServiceProviderEditPage } from "./protocols/oidc/views/serviceProviderEdit.js";
import { renderServiceProviderNewPage } from "./protocols/oidc/views/serviceProviderNew.js";
import { createSamlServiceProviderService, samlServiceProviderStatus } from "./protocols/saml/services/serviceProviders.js";
import { renderSamlServiceProvidersPage } from "./protocols/saml/views/serviceProviders.js";
import { renderSamlServiceProviderNewPage } from "./protocols/saml/views/serviceProviderNew.js";
import { renderSamlServiceProviderEditPage } from "./protocols/saml/views/serviceProviderEdit.js";
import {
  generateAuthnRequestId,
  generateRelayState,
  buildAuthnRequestXml,
  encodeAuthnRequestForRedirect,
  buildSsoRedirectUrl,
  parseIdpMetadata,
  fetchIdpMetadataFromUrl,
  decodeSamlResponse,
  parseSamlResponse,
  maskSamlValue,
  redactSamlRedirectUrl,
  redactSamlXml,
  shortHash,
  summarizeSamlResponseXml,
  summarizeEncodedSamlParam,
  summarizeRelayState,
  summarizeSensitiveValue,
  extractIdpSigningCertificates,
  verifySamlXmlSignatures,
  evaluateSamlTemporalConditions,
  evaluateSamlIssuerValidation,
  evaluateSamlAudienceValidation,
  evaluateSamlDestinationValidation,
  evaluateSamlInResponseTo,
  evaluateSamlSubjectConfirmation,
  checkXswProtection,
  evaluateSamlTrustValidation,
  SAML_CLOCK_SKEW_SECONDS
} from "./protocols/saml/saml.js";
import { createSamlFlowService, SAML_STEP_ORDER } from "./protocols/saml/services/flows.js";
import { renderSamlFlowResultPage } from "./protocols/saml/views/flowResult.js";
import { renderSamlFlowDetailsPage } from "./protocols/saml/views/flowDetails.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const RENDER_EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL || "";
const IS_RENDER = process.env.RENDER === "true" || Boolean(RENDER_EXTERNAL_URL);
const BASE_URL = process.env.BASE_URL || RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const IS_HTTPS_MODE = BASE_URL.startsWith("https://");
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const SESSION_COOKIE = "oidc_debug_sid";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const FLOW_STATE_TTL_MS = 30 * 60 * 1000;
const SAML_FLOW_TTL_MS = 30 * 60 * 1000;
const MAX_BODY_SIZE = 64 * 1024;
const STORAGE_DIR = process.env.STORAGE_DIR || (IS_RENDER ? "/app/storage" : path.join(projectRoot, "data"));
const STATE_FILE = path.join(STORAGE_DIR, "state.json");
const SESSION_SECRET_FILE = path.join(STORAGE_DIR, "session-secret");

const staticFiles = new Map([
  ["/assets/app.css", { filePath: path.join(projectRoot, "public", "app.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/app.js", { filePath: path.join(projectRoot, "public", "app.js"), contentType: "application/javascript; charset=utf-8" }],
  ["/assets/brand/logo.svg", { filePath: path.join(projectRoot, "public", "assets", "brand", "logo.svg"), contentType: "image/svg+xml" }],
  ["/favicon.svg", { filePath: path.join(projectRoot, "public", "assets", "favicon.svg"), contentType: "image/svg+xml" }],
  ["/favicon.ico", { filePath: path.join(projectRoot, "public", "assets", "favicon.ico"), contentType: "image/x-icon" }]
]);

const sessions = new Map();
let providerConfig = createProviderConfig();
let serviceProviders = [];
let flows = [];
let flowSteps = [];
let samlServiceProviders = [];
let samlFlows = [];
let samlFlowSteps = [];
let oidcEnvironmentConfig = {};
let persistTimer = null;
let persistInFlight = Promise.resolve();
let runtimeSessionSecret = process.env.SESSION_SECRET || "";
let runtimeSecretSource = process.env.SESSION_SECRET ? "env" : "pending";
let sessionSigningKey = null;   // HMAC key for session cookies
let encryptionKey = null;       // AES-256-GCM key for client secrets
const serviceProviderService = createServiceProviderService({
  getEntries: () => serviceProviders,
  setEntries: (nextEntries) => {
    serviceProviders = nextEntries;
  },
  createId,
  encryptSecret,
  onChange: schedulePersistState
});
const flowService = createFlowService({
  getFlows: () => flows,
  setFlows: (nextFlows) => {
    flows = nextFlows;
  },
  getSteps: () => flowSteps,
  setSteps: (nextSteps) => {
    flowSteps = nextSteps;
  },
  createId,
  onChange: schedulePersistState
});
const samlServiceProviderService = createSamlServiceProviderService({
  getEntries: () => samlServiceProviders,
  setEntries: (nextEntries) => {
    samlServiceProviders = nextEntries;
  },
  createId,
  onChange: schedulePersistState
});
const samlFlowService = createSamlFlowService({
  getFlows: () => samlFlows,
  setFlows: (nextFlows) => {
    samlFlows = nextFlows;
  },
  getSteps: () => samlFlowSteps,
  setSteps: (nextSteps) => {
    samlFlowSteps = nextSteps;
  },
  createId,
  onChange: schedulePersistState
});
const logLevels = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

function deriveApplicationKeys(masterSecret) {
  sessionSigningKey = crypto.createHmac("sha256", masterSecret).update("oidc-debug:session:v1").digest();
  encryptionKey = crypto.createHmac("sha256", masterSecret).update("oidc-debug:encryption:v1").digest();
}

function createId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function encryptSecret(secret) {
  if (!encryptionKey) throw new Error("Cle de chiffrement non initialisee.");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(String(secret), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    algorithm: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    updatedAt: new Date().toISOString()
  };
}

function decryptSecret(record) {
  if (!record?.ciphertext || !record?.iv || !record?.tag) {
    return "";
  }

  try {
    const decipher = crypto.createDecipheriv(
      record.algorithm || "aes-256-gcm",
      encryptionKey,
      Buffer.from(record.iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(record.tag, "base64"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(record.ciphertext, "base64")),
      decipher.final()
    ]);

    return decrypted.toString("utf8");
  } catch (error) {
    appLog("warn", "decryptSecret failed (wrong key?)", { error: error.message });
    return "";
  }
}

function sanitizeTokenRequest(request) {
  if (!request) {
    return null;
  }

  const headers = redactObject(request.headers || {});
  const params = redactObject(request.params || {});
  const contentType = request.headers?.["content-type"] || "";
  const redactedBody = request.redactedBody || redactBodyText(request.body || "", contentType);
  const redactedCurl = buildCurlCommand({
    url: request.url,
    method: request.method,
    headers,
    body: redactedBody
  });

  return {
    ...request,
    headers,
    params,
    body: "",
    redactedBody,
    curl: redactedCurl
  };
}

function parseSnapshotBody(body = "", contentType = "") {
  if (!body) {
    return null;
  }

  if (typeof body !== "string") {
    return body;
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(body).entries());
  }

  if (contentType.includes("application/json")) {
    return safeJsonParse(body);
  }

  return body;
}

function diagnosticPresence(value) {
  return value === undefined || value === null || value === "" ? "missing" : "present";
}

function diagnosticReceived(value) {
  return value === undefined || value === null || value === "" ? "missing" : "received";
}

function redactProtocolParam(key, value) {
  const normalized = String(key || "").toLowerCase();

  if (normalized === "code_challenge_method") {
    return sanitizeDiagnosticData(value, key);
  }

  if (["state", "nonce", "code_challenge"].includes(normalized)) {
    return diagnosticPresence(value);
  }

  if (["code", "code_verifier"].includes(normalized)) {
    return diagnosticPresence(value);
  }

  return sanitizeDiagnosticData(value, key);
}

function redactProtocolParams(params = {}) {
  return Object.entries(params || {}).reduce((acc, [key, value]) => {
    acc[key] = redactProtocolParam(key, value);
    return acc;
  }, {});
}

function redactDiagnosticUrl(rawUrl = "") {
  if (!rawUrl || typeof rawUrl !== "string") {
    return rawUrl || "";
  }

  try {
    const parsed = new URL(rawUrl, BASE_URL);
    for (const key of Array.from(parsed.searchParams.keys())) {
      const redacted = redactProtocolParam(key, parsed.searchParams.get(key));
      if (redacted !== parsed.searchParams.get(key)) {
        parsed.searchParams.set(key, redacted);
      }
    }

    return rawUrl.startsWith("http://") || rawUrl.startsWith("https://")
      ? parsed.toString()
      : `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return rawUrl;
  }
}

function sanitizeDiagnosticError(value = "") {
  if (!value) {
    return "";
  }

  return String(value)
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi, "$1 ********")
    .replace(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "[redacted-jwt]")
    .replace(/\b(access_token|id_token|refresh_token|client_secret|code_verifier|code|state|nonce)=([^&\s]+)/gi, "$1=********");
}

function lifecycleHash(value = "") {
  return value ? crypto.createHash("sha256").update(String(value)).digest("hex") : "";
}

function lifecycleHashMatches(value = "", expectedHash = "") {
  return Boolean(value && expectedHash && lifecycleHash(value) === expectedHash);
}

function tokenPresence(value) {
  if (["present", "missing", "received", "redacted", "received / redacted", "unavailable", "unknown"].includes(value)) {
    return value;
  }

  return value === undefined || value === null || value === "" ? "missing" : "present";
}

function tokenSummaryStatus(value) {
  if (value === "present" || value === "received" || value === "redacted" || value === "received / redacted") {
    return "received";
  }

  if (value === "missing") {
    return "missing";
  }

  return value === undefined || value === null || value === "" ? "missing" : "received";
}

function claimSummaryStatus(value) {
  if (value === undefined || value === null || value === "" || value === "missing" || value === "no") {
    return "missing";
  }

  if (value === "yes") {
    return "received";
  }

  if (value === "redacted" || value === "received / redacted") {
    return "received / redacted";
  }

  if (value === "received" || value === "present") {
    return "received";
  }

  return "received";
}

function usefulSanitizedHeaders(headers = {}) {
  return sanitizeDiagnosticData(headers || {});
}

function sanitizeAuthorizationRequestRaw(request = {}) {
  return {
    method: request.method || "GET",
    url: redactDiagnosticUrl(request.url || ""),
    headers: usefulSanitizedHeaders(request.headers || {}),
    params: redactProtocolParams(request.params || {})
  };
}

function sanitizeCallbackParams(params = {}) {
  return sanitizeDiagnosticData({
    code: diagnosticPresence(params.code),
    state: diagnosticPresence(params.state),
    ...(params.error ? { error: sanitizeDiagnosticError(params.error) } : {}),
    ...(params.error_description ? { error_description: sanitizeDiagnosticError(params.error_description) } : {})
  });
}

function sanitizeCallbackRaw({ req, params = {}, stateCheck = "" }) {
  const method = req?.method || "GET";
  const localUrl = method === "GET"
    ? redactDiagnosticUrl(req?.url || "/oidc/callback")
    : "/oidc/callback";
  const callbackParams = sanitizeCallbackParams(params);

  return {
    method,
    url: localUrl,
    ...(method === "POST" ? { body: callbackParams } : { query: callbackParams }),
    validation: {
      callback_received: true,
      state_received: Boolean(params.state),
      state_valid: stateCheck === "match",
      provider_error: params.error ? sanitizeDiagnosticError(params.error) : null
    },
    app_response_raw: {
      status: 302,
      ok: true,
      headers: {
        location: "flow result page"
      }
    }
  };
}

function sanitizeTokenRequestRaw(request = {}) {
  const contentType = request.headers?.["content-type"] || request.headers?.["Content-Type"] || "";
  const parsedBody = parseSnapshotBody(request.body || "", contentType) || request.params || {};

  return {
    method: request.method || "POST",
    url: redactDiagnosticUrl(request.url || ""),
    headers: usefulSanitizedHeaders(request.headers || {}),
    body: redactProtocolParams(parsedBody || {})
  };
}

function sanitizeTokenResponseRaw(response = null) {
  if (!response) {
    return null;
  }

  const parsed = response.parsed || parseSnapshotBody(response.body || "", response.headers?.["content-type"] || "") || {};

  return sanitizeDiagnosticData({
    status: response.status ?? 0,
    ok: Boolean(response.ok),
    headers: usefulSanitizedHeaders(response.headers || {}),
    body: {
      access_token: tokenPresence(parsed.access_token),
      id_token: tokenPresence(parsed.id_token),
      refresh_token: tokenPresence(parsed.refresh_token),
      ...(parsed.token_type !== undefined ? { token_type: parsed.token_type } : {}),
      ...(parsed.expires_in !== undefined ? { expires_in: parsed.expires_in } : {}),
      ...(parsed.scope !== undefined ? { scope: parsed.scope } : {}),
      ...(parsed.error !== undefined ? { error: sanitizeDiagnosticError(parsed.error) } : {}),
      ...(parsed.error_description !== undefined ? { error_description: sanitizeDiagnosticError(parsed.error_description) } : {})
    },
    error: response.error ? sanitizeDiagnosticError(response.error) : null
  });
}

function sanitizeUserInfoRequestRaw(request = null) {
  if (!request) {
    return null;
  }

  return {
    method: request.method || "GET",
    url: redactDiagnosticUrl(request.url || ""),
    headers: usefulSanitizedHeaders(request.headers || {}),
    params: {}
  };
}

function sanitizeUserInfoClaims(claims = {}) {
  const sanitized = sanitizeDiagnosticData(claims || {});
  if (!sanitized || typeof sanitized !== "object" || Array.isArray(sanitized)) {
    return sanitized;
  }

  const { claims: _nestedClaims, ...withoutNestedClaims } = sanitized;
  const redactedClaims = { ...withoutNestedClaims };

  for (const key of ["email", "name"]) {
    if (redactedClaims[key] !== undefined && redactedClaims[key] !== null && redactedClaims[key] !== "" && redactedClaims[key] !== "missing") {
      redactedClaims[key] = "received / redacted";
    }
  }

  return redactedClaims;
}

function extractUserInfoClaims(parsed = {}) {
  let claims = parsed || {};

  while (
    claims?.claims &&
    typeof claims.claims === "object" &&
    !Array.isArray(claims.claims) &&
    !claims.raw_claims_available
  ) {
    claims = claims.claims;
  }

  return sanitizeUserInfoClaims(claims);
}

function sanitizeUserInfoResponseRaw(response = null) {
  if (!response) {
    return null;
  }

  const parsed = response.parsed || parseSnapshotBody(response.body || "", response.headers?.["content-type"] || "") || {};
  const claims = extractUserInfoClaims(parsed);

  return {
    status: response.status ?? 0,
    ok: Boolean(response.ok),
    headers: usefulSanitizedHeaders(response.headers || {}),
    body: {
      sub: claims.sub || "missing",
      email: claimSummaryStatus(claims.email),
      name: claimSummaryStatus(claims.name),
      claims
    },
    error: response.error ? sanitizeDiagnosticError(response.error) : null
  };
}

function buildTokenResponseSummary(rawResponseData = null, fallback = {}) {
  const body = rawResponseData?.body || {};

  return {
    ...fallback,
    http_status: rawResponseData?.status ?? fallback.http_status ?? 0,
    access_token: tokenSummaryStatus(body.access_token ?? fallback.access_token),
    id_token: tokenSummaryStatus(body.id_token ?? fallback.id_token),
    refresh_token: tokenSummaryStatus(body.refresh_token ?? fallback.refresh_token),
    expires_in: body.expires_in ?? fallback.expires_in ?? "",
    token_type: body.token_type ?? fallback.token_type ?? "",
    token_error: body.error || rawResponseData?.error || fallback.token_error || "none",
    error_description: body.error_description || fallback.error_description || ""
  };
}

function buildUserInfoResponseSummary(rawResponseData = null, fallback = {}) {
  const body = rawResponseData?.body || {};
  const claims = body.claims && typeof body.claims === "object" ? body.claims : {};
  const claimCount = Object.keys(claims).length;

  return {
    ...fallback,
    called: fallback.called || "yes",
    http_status: rawResponseData?.status ?? fallback.http_status ?? 0,
    subject: body.sub && body.sub !== "missing" ? body.sub : fallback.subject || "",
    email: claimSummaryStatus(body.email ?? fallback.email ?? fallback.email_present),
    name: claimSummaryStatus(body.name ?? fallback.name ?? fallback.name_present),
    raw_claims_available: claimCount > 0 || fallback.raw_claims_available === "yes" ? "yes" : "no",
    error: rawResponseData?.error || fallback.error || "none",
    error_description: fallback.error_description || ""
  };
}

function sanitizeJwtPayload(payload = {}) {
  const claims = sanitizeDiagnosticData(payload || {});
  const usefulClaims = {};

  for (const [key, value] of Object.entries(claims)) {
    if (!["iss", "aud", "sub", "exp", "iat", "nonce"].includes(key)) {
      usefulClaims[key] = value;
    }
  }

  return {
    iss: claims.iss || "",
    aud: claims.aud || "",
    sub: claims.sub || "",
    exp: claims.exp || "",
    iat: claims.iat || "",
    nonce: diagnosticPresence(payload?.nonce),
    ...usefulClaims
  };
}

function evaluateJwtExpiration(exp) {
  const epochSeconds = Number(exp);
  if (!Number.isFinite(epochSeconds)) {
    return "not_checked";
  }

  return epochSeconds * 1000 > Date.now() ? "valid" : "invalid";
}

function buildIdTokenAnalysisRaw(idToken = "", flow = null) {
  const decoded = decodeJwt(idToken || "");
  const expectedIssuer = flow?.runtime?.provider?.issuer || "";
  const expectedAudience = flow?.runtime?.clientId || "";
  const expectedNonce = flow?.runtime?.expectedNonce || "";
  const expectedNonceHash = flow?.runtime?.nonceSha256 || "";

  if (!idToken) {
    return {
      source: "token_response.id_token",
      jwt: null,
      validation: {
        issuer: "not_checked",
        audience: "not_checked",
        expiration: "not_checked",
        nonce: "missing",
        signature: "not_implemented",
        overall: "incomplete"
      },
      decoded: "no",
      claims_readable: "no"
    };
  }

  if (!decoded.isJwt) {
    return {
      source: "token_response.id_token",
      jwt: {
        header: {},
        payload: {}
      },
      validation: {
        issuer: "not_checked",
        audience: "not_checked",
        expiration: "not_checked",
        nonce: "not_checked",
        signature: "not_implemented",
        overall: "incomplete"
      },
      decoded: "no",
      claims_readable: "no",
      error: sanitizeDiagnosticError(decoded.error || "JWT could not be decoded.")
    };
  }

  const payload = decoded.payload || {};
  const audienceValues = Array.isArray(payload.aud) ? payload.aud : [payload.aud].filter(Boolean);
  const nonceClaim = payload.nonce || "";

  return {
    source: "token_response.id_token",
    jwt: {
      header: sanitizeDiagnosticData({
        alg: decoded.header?.alg || "",
        kid: decoded.header?.kid || "",
        ...(decoded.header?.typ ? { typ: decoded.header.typ } : {})
      }),
      payload: sanitizeJwtPayload(payload)
    },
    validation: {
      issuer: expectedIssuer ? (payload.iss === expectedIssuer ? "valid" : "invalid") : "not_checked",
      audience: expectedAudience ? (audienceValues.includes(expectedAudience) ? "valid" : "invalid") : "not_checked",
      expiration: evaluateJwtExpiration(payload.exp),
      nonce: expectedNonce
        ? (nonceClaim ? (nonceClaim === expectedNonce ? "valid" : "invalid") : "missing")
        : expectedNonceHash
          ? (nonceClaim ? (lifecycleHashMatches(nonceClaim, expectedNonceHash) ? "valid" : "invalid") : "missing")
          : "not_checked",
      signature: "not_implemented",
      overall: "incomplete"
    },
    decoded: "yes",
    claims_readable: "yes"
  };
}

function sanitizeRawRequest(request = null) {
  if (!request) {
    return null;
  }

  const headers = sanitizeDiagnosticData(request.headers || {});
  const contentType = request.headers?.["content-type"] || request.headers?.["Content-Type"] || "";
  const parsedBody = parseSnapshotBody(request.body || "", contentType);

  return sanitizeDiagnosticData({
    method: request.method || "",
    url: redactDiagnosticUrl(request.url || ""),
    headers,
    params: redactProtocolParams(request.params || {}),
    body: parsedBody && typeof parsedBody === "object" ? redactProtocolParams(parsedBody) : parsedBody || undefined
  });
}

function summarizeUserInfoClaims(claims = {}) {
  const keys = Object.keys(claims || {});

  return {
    sub: claims.sub || "",
    email: diagnosticReceived(claims.email),
    name: diagnosticReceived(claims.name),
    raw_claims_available: keys.length > 0 ? "yes" : "no",
    claim_count: keys.length,
    body_redaction: keys.length > 0 ? "PII claims limited for display" : ""
  };
}

function sanitizeRawResponse(response = null, { bodyMode = "default" } = {}) {
  if (!response) {
    return null;
  }

  const contentType = response.headers?.["content-type"] || response.headers?.["Content-Type"] || "";
  const parsedBody = response.parsed || parseSnapshotBody(response.body || "", contentType);
  const body = bodyMode === "userinfo" && parsedBody && typeof parsedBody === "object"
    ? summarizeUserInfoClaims(parsedBody)
    : parsedBody || response.redactedBody || response.error || "";

  return sanitizeDiagnosticData({
    status: response.status ?? 0,
    ok: Boolean(response.ok),
    headers: usefulSanitizedHeaders(response.headers || {}),
    body,
    error: response.error ? sanitizeDiagnosticError(response.error) : "",
    diagnostics: response.diagnostics || null
  });
}

function callbackStateCheckFromStep(step = {}) {
  const value = step.responseData?.state_validation || step.responseData?.state || step.rawResponseData?.state_validation || step.rawResponseData?.state || "";
  if (value === "valid" || value === "match") {
    return "match";
  }
  if (value === "missing" || value === "mismatch") {
    return value;
  }
  return "";
}

function sanitizeCallbackRawFromStep(step = {}) {
  const raw = step.rawRequestData || step.rawResponseData || {};
  const params = raw.query || raw.body || raw.params || {
    code: step.responseData?.authorization_code,
    state: step.responseData?.state,
    error: step.responseData?.error,
    error_description: step.responseData?.error_description
  };

  return sanitizeCallbackRaw({
    req: {
      method: raw.method || step.httpMethod || "GET",
      url: raw.url || "/oidc/callback"
    },
    params,
    stateCheck: callbackStateCheckFromStep(step)
  });
}

function sanitizeOidcRawRequestForStep(stepName, rawRequestData, step = {}) {
  if (!rawRequestData) {
    return null;
  }

  if (stepName === "authorize") {
    return sanitizeAuthorizationRequestRaw(rawRequestData);
  }

  if (stepName === "callback") {
    return sanitizeCallbackRawFromStep(step);
  }

  if (stepName === "token") {
    return sanitizeTokenRequestRaw(rawRequestData);
  }

  if (stepName === "userinfo") {
    return sanitizeUserInfoRequestRaw(rawRequestData);
  }

  return sanitizeRawRequest(rawRequestData);
}

function sanitizeOidcRawResponseForStep(stepName, rawResponseData, step = {}) {
  if (!rawResponseData) {
    return null;
  }

  if (stepName === "callback") {
    return sanitizeCallbackRawFromStep(step);
  }

  if (stepName === "token") {
    return sanitizeTokenResponseRaw(rawResponseData);
  }

  if (stepName === "userinfo") {
    return sanitizeUserInfoResponseRaw(rawResponseData);
  }

  if (rawResponseData.body && typeof rawResponseData.body === "object") {
    return sanitizeDiagnosticData(rawResponseData);
  }

  return sanitizeRawResponse(rawResponseData);
}

function sanitizeProviderConfig(input = providerConfig) {
  return normalizeProviderConfig(input);
}

function sanitizeServiceProviderForUi(serviceProvider) {
  if (!serviceProvider) {
    return null;
  }

  const normalized = normalizeServiceProvider(serviceProvider, serviceProvider);
  const environment = getEzAccessEnvironment(serviceProvider.environment || "");

  return {
    ...normalized,
    environment: environment?.key || "",
    environmentLabel: environment?.key === "preprod" ? "Preprod" : environment?.key === "prod" ? "Prod" : "",
    scopes: normalized.scopes,
    secretConfigured: Boolean(serviceProvider.secretRecord?.ciphertext),
    status: serviceProviderStatus(serviceProvider),
    createdAt: serviceProvider.createdAt || null,
    updatedAt: serviceProvider.updatedAt || null
  };
}

function sanitizeSamlServiceProviderForUi(sp) {
  if (!sp) return null;
  const environment = getEzAccessEnvironment(sp.environment || "");
  return {
    ...sp,
    environment: environment?.key || "",
    environmentLabel: environment?.key === "preprod" ? "Preprod" : environment?.key === "prod" ? "Prod" : "",
    acsUrl: `${BASE_URL}/saml/acs/${sp.id}`,
    status: samlServiceProviderStatus(sp)
  };
}

function sanitizeEzAccessEnvironmentForUi(environment) {
  return {
    key: environment.key,
    label: environment.label,
    shortLabel: environment.key === "preprod" ? "Preprod" : "Prod",
    discoveryConfigured: Boolean(environment.discoveryUrl)
  };
}

function sanitizeSessionArtifacts(session) {
  return {
    ...session,
    runtimeContext: session.runtimeContext
      ? {
          ...session.runtimeContext
        }
      : null,
    flow: {
      statePresent: session.flow?.expectedState ? "present" : "missing",
      noncePresent: session.flow?.expectedNonce ? "present" : "missing",
      codeVerifierPresent: session.flow?.codeVerifier ? "present" : "missing",
      codeChallengePresent: session.flow?.codeChallenge ? "present" : "missing"
    },
    steps: {
      ...session.steps,
      token: session.steps?.token
        ? {
            ...session.steps.token,
            request: sanitizeTokenRequest(session.steps.token.request)
          }
        : null
    },
    tokens: session.tokens ? sanitizeDiagnosticData(session.tokens) : null,
    logs: Array.isArray(session.logs) ? sanitizeDiagnosticData(session.logs) : []
  };
}

function createSession() {
  const id = crypto.randomBytes(24).toString("hex");
  return {
    id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    selectedServiceProviderId: "",
    runtimeContext: null,
    flow: {
      expectedState: "",
      expectedNonce: "",
      codeVerifier: "",
      codeChallenge: ""
    },
    steps: {
      discovery: null,
      authorize: null,
      callback: null,
      token: null,
      userinfo: null
    },
    tokens: null,
    comparison: null,
    logs: [],
    flash: null
  };
}

function sanitizeTerminalOidcFlow(flow) {
  if (!flow || !flow.runtime) {
    return flow;
  }

  return {
    ...flow,
    runtime: sanitizeTerminalOidcRuntime(flow.runtime)
  };
}

function sanitizeTerminalOidcRuntime(flowRuntime = {}) {
  const {
    expectedState,
    expectedNonce,
    codeVerifier,
    codeChallenge,
    ...runtime
  } = flowRuntime;

  return {
    ...runtime,
    stateSha256: runtime.stateSha256 || lifecycleHash(expectedState),
    nonceSha256: runtime.nonceSha256 || lifecycleHash(expectedNonce),
    pkceMethod: codeChallenge ? "S256" : runtime.pkceMethod || "",
    codeChallengePresent: codeChallenge ? "yes" : runtime.codeChallengePresent || "no",
    codeVerifierPresent: codeVerifier ? "yes" : runtime.codeVerifierPresent || "no",
    stateGenerated: expectedState ? "yes" : runtime.stateGenerated || "no",
    stateSent: expectedState ? "yes" : runtime.stateSent || "no",
    nonceGenerated: expectedNonce ? "yes" : runtime.nonceGenerated || "no",
    nonceSent: expectedNonce ? "yes" : runtime.nonceSent || "no"
  };
}

function sanitizeOidcStepForPersistence(step = {}) {
  const responseData = step.responseData?.authorization_url_full
    ? {
        ...step.responseData,
        authorization_url_full: redactDiagnosticUrl(step.responseData.authorization_url_full)
      }
    : step.responseData;
  const rawResponseData = step.rawResponseData
    ? sanitizeOidcRawResponseForStep(step.stepName, step.rawResponseData, step)
    : step.rawResponseData;

  return {
    ...step,
    responseData,
    rawRequestData: step.rawRequestData
      ? sanitizeOidcRawRequestForStep(step.stepName, step.rawRequestData, step)
      : step.rawRequestData,
    rawResponseData,
    rawAnalysisData: step.rawAnalysisData ? sanitizeDiagnosticData(step.rawAnalysisData) : null
  };
}

function sanitizeSamlRuntimeForPersistence(runtime = null) {
  if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) return runtime;
  const next = { ...runtime };
  if (typeof next.relayState === "string" && next.relayState && next.relayState !== "received / redacted") {
    next.relayStateSha25612 = next.relayStateSha25612 || shortHash(next.relayState);
    next.relayState = "received / redacted";
    next.relayStatePresent = true;
  }
  if (typeof next.authorizationUrl === "string" && next.authorizationUrl) {
    next.authorizationUrl = redactSamlRedirectUrl(next.authorizationUrl);
    next.authorizationUrlNature = next.authorizationUrlNature || "redacted browser redirect URL";
  }
  return sanitizeSamlDiagnosticValue(next);
}

function sanitizeSamlFlowForPersistence(flow = {}) {
  return {
    ...flow,
    runtime: sanitizeSamlRuntimeForPersistence(flow.runtime)
  };
}

function sanitizeSamlStepForPersistence(step = {}) {
  return {
    ...step,
    requestData: sanitizeSamlDiagnosticValue(step.requestData || null),
    responseData: sanitizeSamlDiagnosticValue(step.responseData || null),
    rawRequestData: sanitizeSamlDiagnosticValue(step.rawRequestData || null),
    rawResponseData: sanitizeSamlDiagnosticValue(step.rawResponseData || null),
    errorData: sanitizeSamlDiagnosticValue(step.errorData || null)
  };
}

function buildPersistedState() {
  return {
    version: 4,
    updatedAt: new Date().toISOString(),
    oidc: {
      providerConfig: sanitizeProviderConfig(providerConfig),
      environmentConfig: oidcEnvironmentConfig,
      serviceProviders,
      flows: flows.map(sanitizeTerminalOidcFlow),
      flowSteps: flowSteps.map(sanitizeOidcStepForPersistence)
    },
    saml: {
      serviceProviders: samlServiceProviders,
      flows: samlFlows.map(sanitizeSamlFlowForPersistence),
      flowSteps: samlFlowSteps.map(sanitizeSamlStepForPersistence)
    },
    sessions: Array.from(sessions.values()).map((session) => ({
      ...sanitizeSessionArtifacts(session),
      flash: null
    }))
  };
}

async function persistStateNow() {
  await mkdir(STORAGE_DIR, { recursive: true });
  const tempFile = `${STATE_FILE}.tmp`;
  await writeFile(tempFile, JSON.stringify(buildPersistedState(), null, 2), { encoding: "utf8", mode: 0o600 });
  await rename(tempFile, STATE_FILE);
}

function schedulePersistState() {
  if (persistTimer) {
    clearTimeout(persistTimer);
  }

  persistTimer = setTimeout(() => {
    persistTimer = null;
    persistInFlight = persistInFlight
      .then(() => persistStateNow())
      .catch((error) => {
        appLog("error", "Failed to persist application state", {
          error: error.message,
          stateFile: STATE_FILE
        });
      });
  }, 150);
}

async function flushPersistState() {
  if (persistTimer) {
    clearTimeout(persistTimer);
    persistTimer = null;
  }

  persistInFlight = persistInFlight
    .then(() => persistStateNow())
    .catch((error) => {
      appLog("error", "Failed to persist application state", {
        error: error.message,
        stateFile: STATE_FILE
      });
    });

  await persistInFlight;
}

function migrateLegacyToV2(parsed = {}) {
  const legacyProvider = parsed?.defaultConfig || {};
  const nextProviderConfig = normalizeProviderConfig({
    providerName: legacyProvider.providerName,
    discoveryUrl: legacyProvider.discoveryUrl,
    issuer: legacyProvider.issuer,
    authorizationEndpoint: legacyProvider.authorizationEndpoint,
    tokenEndpoint: legacyProvider.tokenEndpoint,
    userInfoEndpoint: legacyProvider.userInfoEndpoint,
    jwksUri: legacyProvider.jwksUri
  });

  const migratedServiceProviders = [];

  if (legacyProvider.clientId) {
    migratedServiceProviders.push({
      id: createId("sp"),
      name: legacyProvider.providerName ? `${legacyProvider.providerName} principal` : "SP migre",
      clientId: legacyProvider.clientId,
      clientType: legacyProvider.clientType === "public" ? "public" : "confidential",
      secretRecord: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
  }

  return {
    version: 2,
    updatedAt: new Date().toISOString(),
    providerConfig: nextProviderConfig,
    serviceProviders: migratedServiceProviders,
    flows: [],
    flowSteps: [],
    sessions: []
  };
}

function migrateState(parsed = {}) {
  if (!parsed.version || parsed.version < 2) {
    return migrateState(migrateLegacyToV2(parsed));
  }

  if (parsed.version === 2) {
    return migrateState({
      version: 3,
      updatedAt: parsed.updatedAt || new Date().toISOString(),
      providerConfig: parsed.providerConfig || {},
      oidc: {
        serviceProviders: parsed.serviceProviders || [],
        flows: parsed.flows || [],
        flowSteps: parsed.flowSteps || []
      },
      sessions: parsed.sessions || []
    });
  }

  if (parsed.version === 3) {
    return {
      version: 4,
      updatedAt: parsed.updatedAt || new Date().toISOString(),
      oidc: {
        providerConfig: parsed.providerConfig || parsed.oidc?.providerConfig || {},
        serviceProviders: parsed.oidc?.serviceProviders || [],
        flows: parsed.oidc?.flows || [],
        flowSteps: parsed.oidc?.flowSteps || []
      },
      saml: {
        serviceProviders: parsed.saml?.serviceProviders || [],
        flows: parsed.saml?.flows || [],
        flowSteps: parsed.saml?.flowSteps || []
      },
      sessions: parsed.sessions || []
    };
  }

  return parsed;
}

async function loadPersistedState() {
  try {
    const raw = await readFile(STATE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    const hydrated = migrateState(parsed);

    providerConfig = sanitizeProviderConfig(hydrated.oidc?.providerConfig);
    oidcEnvironmentConfig = hydrated.oidc?.environmentConfig || {};
    serviceProviderService.hydrateServiceProviders(hydrated.oidc?.serviceProviders || []);
    flowService.hydrateFlows(
      (hydrated.oidc?.flows || []).map(sanitizeTerminalOidcFlow),
      (hydrated.oidc?.flowSteps || []).map(sanitizeOidcStepForPersistence)
    );
    samlServiceProviderService.hydrateSamlServiceProviders(hydrated.saml?.serviceProviders || []);
    samlFlowService.hydrateSamlFlows(hydrated.saml?.flows || [], hydrated.saml?.flowSteps || []);
    if ((hydrated.saml?.flows || []).length || (hydrated.saml?.flowSteps || []).length) {
      schedulePersistState();
    }

    for (const candidate of hydrated.sessions || []) {
      if (!candidate?.id) {
        continue;
      }

      sessions.set(candidate.id, {
        id: candidate.id,
        createdAt: candidate.createdAt || new Date().toISOString(),
        updatedAt: candidate.updatedAt || new Date().toISOString(),
        selectedServiceProviderId: candidate.selectedServiceProviderId || "",
        runtimeContext: candidate.runtimeContext || null,
        flow: {
          expectedState: candidate.flow?.expectedState && candidate.flow.expectedState !== "present" ? candidate.flow.expectedState : "",
          expectedNonce: candidate.flow?.expectedNonce && candidate.flow.expectedNonce !== "present" ? candidate.flow.expectedNonce : "",
          codeVerifier: candidate.flow?.codeVerifier && candidate.flow.codeVerifier !== "present" ? candidate.flow.codeVerifier : "",
          codeChallenge: candidate.flow?.codeChallenge && candidate.flow.codeChallenge !== "present" ? candidate.flow.codeChallenge : ""
        },
        steps: {
          discovery: candidate.steps?.discovery || null,
          authorize: candidate.steps?.authorize || null,
          callback: candidate.steps?.callback || null,
          token: candidate.steps?.token
            ? {
                ...candidate.steps.token,
                request: sanitizeTokenRequest(candidate.steps.token.request)
              }
            : null,
          userinfo: candidate.steps?.userinfo || null
        },
        tokens: candidate.tokens || null,
        comparison: candidate.comparison || null,
        logs: Array.isArray(candidate.logs) ? candidate.logs : [],
        flash: null
      });
    }

    appLog("info", "Etat applicatif restaure depuis le disque", {
      stateFile: STATE_FILE,
      sessions: sessions.size,
      oidcServiceProviders: serviceProviders.length,
      oidcFlows: flows.length,
      samlServiceProviders: samlServiceProviders.length
    });

    await persistStateNow();
  } catch (error) {
    if (error.code === "ENOENT") {
      appLog("info", "No persisted state found, starting with empty state", {
        stateFile: STATE_FILE
      });
      return;
    }

    appLog("error", "Unable to load persisted state", {
      error: error.message,
      stateFile: STATE_FILE
    });
  }
}

const SESSION_SECRET_MIN_LENGTH = 32;

async function ensureRuntimeSecrets() {
  if (process.env.SESSION_SECRET) {
    runtimeSessionSecret = process.env.SESSION_SECRET;
    runtimeSecretSource = "env";
    if (runtimeSessionSecret.length < SESSION_SECRET_MIN_LENGTH) {
      appLog("warn", `SESSION_SECRET trop court (${runtimeSessionSecret.length} chars, minimum ${SESSION_SECRET_MIN_LENGTH}). Utilisez une valeur aleatoire robuste en production.`);
    }
    deriveApplicationKeys(runtimeSessionSecret);
    return;
  }

  await mkdir(STORAGE_DIR, { recursive: true });

  try {
    runtimeSessionSecret = (await readFile(SESSION_SECRET_FILE, "utf8")).trim();
    runtimeSecretSource = "file";
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }

    runtimeSessionSecret = crypto.randomUUID();
    runtimeSecretSource = "generated-file";
    await writeFile(SESSION_SECRET_FILE, `${runtimeSessionSecret}\n`, {
      encoding: "utf8",
      mode: 0o600
    });
  }

  deriveApplicationKeys(runtimeSessionSecret);
}

function cleanupSessions() {
  const deadline = Date.now() - SESSION_TTL_MS;
  let removed = false;

  for (const [id, session] of sessions.entries()) {
    const updatedAt = new Date(session.updatedAt).getTime();
    if (updatedAt < deadline) {
      sessions.delete(id);
      removed = true;
    }
  }

  if (removed) {
    schedulePersistState();
  }
}

setInterval(cleanupSessions, 15 * 60 * 1000).unref();

function parseCookies(cookieHeader = "") {
  return cookieHeader
    .split(";")
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const separator = part.indexOf("=");
      if (separator === -1) {
        return acc;
      }

      const key = part.slice(0, separator);
      const value = part.slice(separator + 1);
      acc[key] = decodeURIComponent(value);
      return acc;
    }, {});
}

function setSessionCookie(res, sessionId) {
  const signature = crypto.createHmac("sha256", sessionSigningKey).update(sessionId).digest("hex").slice(0, 16);
  const value = `${sessionId}.${signature}`;
  const secureFlag = IS_HTTPS_MODE ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`);
}

function decodeSessionCookie(rawValue = "") {
  if (!rawValue) {
    return null;
  }

  const [sessionId, signature] = rawValue.split(".");
  if (!sessionId || !signature) {
    return null;
  }

  const expected = crypto.createHmac("sha256", sessionSigningKey).update(sessionId).digest("hex").slice(0, 16);
  if (signature.length !== expected.length) {
    return null;
  }

  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)) ? sessionId : null;
}

function touchSession(session) {
  session.updatedAt = new Date().toISOString();
  schedulePersistState();
}

function getOrCreateSession(req, res) {
  const cookies = parseCookies(req.headers.cookie || "");
  const raw = cookies[SESSION_COOKIE];
  const sessionId = decodeSessionCookie(raw);

  if (sessionId && sessions.has(sessionId)) {
    const session = sessions.get(sessionId);
    touchSession(session);
    return session;
  }

  const session = createSession();
  sessions.set(session.id, session);
  setSessionCookie(res, session.id);
  touchSession(session);
  appLog("info", "Nouvelle session creee", { sessionId: session.id });
  return session;
}

function addSessionLog(session, level, event, message, data = null) {
  session.logs.push({
    id: crypto.randomBytes(6).toString("hex"),
    time: new Date().toISOString(),
    level,
    event,
    message,
    data: data ? sanitizeDiagnosticData(redactObject(data)) : null
  });
  touchSession(session);
  appLog(level, message, sanitizeDiagnosticData({ event, ...(data || {}) }));
}

function setFlash(session, level, message) {
  session.flash = {
    level,
    message
  };
  schedulePersistState();
}

function consumeFlash(session) {
  const flash = session.flash;
  session.flash = null;
  schedulePersistState();
  return flash;
}

function getServiceProvider(serviceProviderId) {
  return serviceProviderService.getServiceProvider(serviceProviderId);
}

function resetFlowState(session, reason = "configuration_changed") {
  session.runtimeContext = null;
  session.flow = {
    expectedState: "",
    expectedNonce: "",
    codeVerifier: "",
    codeChallenge: ""
  };
  session.steps.authorize = null;
  session.steps.callback = null;
  session.steps.token = null;
  session.steps.userinfo = null;
  session.tokens = null;
  session.comparison = null;
  touchSession(session);

  addSessionLog(session, "info", "flow_reset", "Les etapes du test ont ete reinitialisees.", {
    reason
  });
}

function removeServiceProvider(serviceProviderId) {
  const removed = serviceProviderService.deleteServiceProvider(serviceProviderId);

  for (const session of sessions.values()) {
    if (session.selectedServiceProviderId === serviceProviderId) {
      session.selectedServiceProviderId = "";
      resetFlowState(session, "service_provider_deleted");
    }
  }

  schedulePersistState();
  return removed;
}

function shouldLog(level) {
  return (logLevels[level] || 20) >= (logLevels[LOG_LEVEL] || 20);
}

function appLog(level, message, data) {
  if (!shouldLog(level)) {
    return;
  }

  const redacted = data ? JSON.stringify(redactObject(data)) : "";
  const line = `[oidc_debug] ${level.toUpperCase()} ${message}${redacted ? ` ${redacted}` : ""}`;

  if (level === "error") {
    console.error(line);
    return;
  }

  if (level === "warn") {
    console.warn(line);
    return;
  }

  console.log(line);
}

async function readBody(req) {
  const chunks = [];
  let totalSize = 0;
  for await (const chunk of req) {
    totalSize += chunk.length;
    if (totalSize > MAX_BODY_SIZE) {
      req.resume();
      const err = new Error("Request body exceeds size limit.");
      err.code = "BODY_TOO_LARGE";
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseBody(req, rawBody) {
  const contentType = req.headers["content-type"] || "";

  if (contentType.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(rawBody).entries());
  }

  if (contentType.includes("application/json")) {
    return safeJsonParse(rawBody) || {};
  }

  return {};
}

function pickSamlDiagnosticHeaders(headers = {}) {
  const allowed = [
    "accept",
    "content-type",
    "origin",
    "referer",
    "user-agent",
    "host",
    "x-forwarded-host",
    "x-forwarded-proto"
  ];
  const result = {};
  for (const name of allowed) {
    const value = headers[name];
    if (value) {
      result[name] = String(value);
    }
  }
  return result;
}

function samlParamPresence(searchParams, name) {
  const value = searchParams.get(name) || "";
  return value ? summarizeSensitiveValue(value) : { present: false };
}

function samlParamStatus(searchParams, name) {
  return (searchParams.get(name) || "") ? "present" : "missing";
}

function compareDiagnostic(actual, expected) {
  if (!actual) return "missing";
  if (!expected) return "not_checked";
  return actual === expected ? "match" : "mismatch";
}

function buildPreparedRedirectSummary(authorizationUrl = "") {
  const searchParams = authorizationUrl ? new URL(authorizationUrl).searchParams : new URLSearchParams();
  return {
    method: "GET",
    url: authorizationUrl ? redactSamlRedirectUrl(authorizationUrl) : "",
    params: {
      SAMLRequest: samlParamStatus(searchParams, "SAMLRequest"),
      RelayState: samlParamStatus(searchParams, "RelayState"),
      SigAlg: samlParamStatus(searchParams, "SigAlg"),
      Signature: samlParamStatus(searchParams, "Signature")
    }
  };
}

function buildSamlAuthnRequestRaw({ authnRequestXml, requestId, issueInstant, idpMetadata, sp, acsUrl, samlRequestParam, relayState, authorizationUrl = "" }) {
  return {
    raw_type: "Prepared SAML AuthnRequest",
    is_real_http_exchange: false,
    source: "local generation before browser redirect",
    timestamp: new Date().toISOString(),
    binding: idpMetadata.ssoBinding === "HTTP-Redirect" ? "HTTP-Redirect" : "not implemented",
    metadata_selected_binding: idpMetadata.ssoBinding || "not found",
    request_id: requestId,
    sp_entity_id: sp.spEntityId,
    acs_url: acsUrl,
    destination_idp: idpMetadata.ssoUrl,
    issue_instant: issueInstant,
    name_id_format: sp.nameIdFormat || "(unspecified)",
    expected_response_protocol_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    prepared_http_redirect: buildPreparedRedirectSummary(authorizationUrl),
    xml_redacted: redactSamlXml(authnRequestXml),
    xml_size_bytes: Buffer.byteLength(authnRequestXml || "", "utf8"),
    xml_sha256_12: shortHash(authnRequestXml),
    encoded_saml_request: {
      ...summarizeEncodedSamlParam(samlRequestParam),
      encoding: samlRequestParam ? "deflate+base64" : "not encoded"
    },
    relay_state: summarizeRelayState(relayState),
    signature: {
      authn_request_signature: "not implemented",
      sig_alg_param: "missing",
      signature_param: "missing"
    }
  };
}

function buildSamlRedirectRaw({ authorizationUrl, idpMetadata, samlRequestParam, relayState }) {
  const searchParams = authorizationUrl ? new URL(authorizationUrl).searchParams : new URLSearchParams();
  return {
    raw_type: "Prepared browser redirect",
    is_real_http_exchange: false,
    source: "synthetic local 302 response prepared by this app",
    timestamp: new Date().toISOString(),
    method: "GET",
    local_status: 302,
    binding: "HTTP-Redirect",
    sso_url: idpMetadata.ssoUrl,
    url: authorizationUrl ? redactSamlRedirectUrl(authorizationUrl) : "",
    params: {
      SAMLRequest: samlParamStatus(searchParams, "SAMLRequest"),
      RelayState: samlParamStatus(searchParams, "RelayState"),
      SigAlg: samlParamStatus(searchParams, "SigAlg"),
      Signature: samlParamStatus(searchParams, "Signature")
    },
    query_param_summaries: {
      SAMLRequest: samlParamPresence(searchParams, "SAMLRequest"),
      RelayState: searchParams.get("RelayState") ? summarizeRelayState(searchParams.get("RelayState")) : { present: false },
      SigAlg: samlParamPresence(searchParams, "SigAlg"),
      Signature: samlParamPresence(searchParams, "Signature")
    },
    note: "Prepared local browser redirect, not an IdP response."
  };
}

function buildSamlSyntheticResponseRaw({ rawType = "Synthetic local response", status = 302, note = "" } = {}) {
  return {
    raw_type: rawType,
    is_real_http_exchange: false,
    timestamp: new Date().toISOString(),
    local_status: status,
    note
  };
}

function buildUnsupportedSamlBindingRaw(idpMetadata) {
  return {
    raw_type: "Not implemented",
    is_real_http_exchange: false,
    source: "metadata binding selection",
    timestamp: new Date().toISOString(),
    selected_metadata_binding: idpMetadata.ssoBinding || "not found",
    supported_request_binding: "HTTP-Redirect",
    diagnostic_warning: "HTTP-POST AuthnRequest binding not implemented",
    action: "Flow stopped before building an incoherent Redirect URL."
  };
}

function buildSamlAcsRequestRaw({ req, url, body, samlResponseParam, relayState }) {
  return {
    raw_type: "Reconstructed inbound ACS request",
    is_real_http_exchange: true,
    source: "parsed inbound HTTP request with sensitive fields summarized",
    timestamp: new Date().toISOString(),
    method: req.method || "POST",
    path: url.pathname,
    content_type: req.headers["content-type"] || "",
    headers: pickSamlDiagnosticHeaders(req.headers),
    body_fields: {
      SAMLResponse: summarizeEncodedSamlParam(samlResponseParam || body.SAMLResponse || ""),
      RelayState: relayState ? summarizeRelayState(relayState) : { present: "missing" }
    }
  };
}

function buildDecodedSamlResponseRaw({ responseXml, samlResponseParam, relayState, path }) {
  const summary = summarizeSamlResponseXml(responseXml);
  return {
    raw_type: "Decoded SAMLResponse redacted",
    is_real_http_exchange: false,
    source: "SAMLResponse form field from ACS POST",
    timestamp: new Date().toISOString(),
    method: "POST",
    path,
    base64: summarizeEncodedSamlParam(samlResponseParam),
    response_id: summary.response_id,
    assertion_id: summary.assertion_id,
    issuer: summary.issuer,
    in_response_to: summary.in_response_to,
    destination: summary.destination,
    status_code: summary.status_code,
    status_message: sanitizeSamlDiagnosticValue(summary.status_message || "(not extracted)", "status_message"),
    status_detail: summary.status_detail,
    signatures: summary.signatures,
    certificates: summary.certificates,
    xml: {
      decoded: Boolean(responseXml),
      size_bytes: responseXml ? Buffer.byteLength(responseXml, "utf8") : 0,
      sha256_12: responseXml ? shortHash(responseXml) : "",
      redacted: responseXml ? redactSamlXml(responseXml) : ""
    }
  };
}

function buildEncodedSamlResponseRaw({ samlResponseParam, relayState, path }) {
  return {
    raw_type: "SAMLResponse form field summary",
    is_real_http_exchange: false,
    source: "SAMLResponse form field from ACS POST",
    timestamp: new Date().toISOString(),
    method: "POST",
    path,
    base64: summarizeEncodedSamlParam(samlResponseParam),
    relay_state: relayState ? summarizeRelayState(relayState) : { present: false }
  };
}

function buildSamlDecodeErrorRaw({ samlResponseParam, relayState, path }) {
  return {
    raw_type: "Decoded SAMLResponse redacted",
    is_real_http_exchange: false,
    source: "SAMLResponse form field from ACS POST",
    timestamp: new Date().toISOString(),
    method: "POST",
    path,
    decode_status: "error",
    base64: summarizeEncodedSamlParam(samlResponseParam),
    xml: {
      decoded: false
    },
    relay_state: relayState ? summarizeRelayState(relayState) : { present: false }
  };
}

function buildParsedSamlSummaryRaw({
  parsed, diagnostics, attrCount, sigVerification, idpCertFingerprints,
  trustResult, xswProtection, issuerValidation, audienceValidation,
  destinationValidation, inResponseToValidation, subjectConfirmationValidation,
  temporalValidation, replayValidation, metadataCertificates
}) {
  const statusMessage = sanitizeSamlDiagnosticValue(parsed.statusMessage || "(not extracted)", "status_message");
  const sv = sigVerification || {};
  const tr = trustResult || {};
  return {
    raw_type: "Parsed SAMLResponse summary redacted",
    is_real_http_exchange: false,
    timestamp: new Date().toISOString(),
    response: {
      response_id: parsed.responseIdSummary || { present: false },
      issuer: parsed.issuer || "(not found)",
      in_response_to: parsed.inResponseTo || "(not found)",
      destination: parsed.destination || "(not found)",
      status_code: parsed.statusCode || "(not found)",
      status_message: statusMessage,
      status_detail: parsed.statusDetailPresent ? "present" : "missing"
    },
    assertion: {
      present: parsed.assertionPresent ? "yes" : "no",
      assertion_id: parsed.assertionIdSummary || { present: false },
      issuer: parsed.assertionIssuer || "(not extracted)",
      subject_present: parsed.subjectPresent ? "yes" : "no",
      name_id_present: parsed.nameIdPresent ? "yes" : "no",
      name_id_preview: parsed.nameIdPreview || "(not present)",
      name_id_hash: parsed.nameIdHash || "",
      name_id_format: parsed.nameIdFormat || "(not present)",
      attributes_count: attrCount,
      attribute_names: parsed.attributeNames || [],
      attributes_redacted: parsed.attributes || {},
      session_index: parsed.sessionIndexPresent
        ? { present: true, sha256_12: parsed.sessionIndexHash }
        : { present: false },
      conditions_present: parsed.conditionsPresent ? "yes" : "no",
      conditions_evaluated: temporalValidation?.conditions_evaluated ? "yes" : "no",
      temporal_conditions_status: temporalValidation?.result || "not_checked",
      audience_restriction_present: parsed.audienceRestrictionPresent ? "yes" : "no",
      audience: parsed.audience || "(not extracted)",
      subject_confirmation_present: parsed.subjectConfirmationPresent ? "yes" : "no",
      recipient: parsed.recipient || "(not extracted)",
      not_before: parsed.notBefore || "(not extracted)",
      not_on_or_after: parsed.notOnOrAfter || "(not extracted)"
    },
    signature: {
      response_signature: sv.response_signature_present || "not extracted",
      response_verification: sv.response_signature_verification || "not_checked",
      assertion_signature: sv.assertion_signature_present || "not extracted",
      assertion_verification: sv.assertion_signature_verification || "not_checked",
      verification_result: sv.signature_verification_result || "not_checked",
      trusted_idp_certificates: metadataCertificates || { available: false, count: 0, source: "idp_metadata" },
      ...(sv.response_verification_error ? { response_error: sv.response_verification_error } : {}),
      ...(sv.assertion_verification_error ? { assertion_error: sv.assertion_verification_error } : {})
    },
    trust_validation: {
      trust_validation: tr.trust_validation || "incomplete",
      overall_result: tr.overall_result || "unverified",
      checks: tr.checks || {},
      warnings: tr.warnings || [],
      errors: tr.errors || [],
      metadata_certificates: metadataCertificates || { available: false, count: 0, source: "idp_metadata" },
      issuer_validation: issuerValidation || { result: "not_checked" },
      audience_validation: audienceValidation || { result: "not_checked" },
      destination_validation: destinationValidation || { result: "not_checked" },
      in_response_to_validation: inResponseToValidation || { result: "not_checked" },
      subject_confirmation_validation: subjectConfirmationValidation || { result: "not_checked" },
      temporal_validation: temporalValidation || { result: "not_checked" },
      xsw_protection: xswProtection || { result: "incomplete" },
      replay_validation: replayValidation || { result: "not_implemented" }
    },
    diagnostic_comparisons: diagnostics
  };
}

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  ...(IS_HTTPS_MODE ? { "strict-transport-security": "max-age=63072000; includeSubDomains" } : {})
};

const rateLimitMap = new Map();

// SAML replay protection — stores full sha256 hashes of seen response/assertion IDs
const samlSeenIds = new Map();
const SAML_REPLAY_TTL_MS = 8 * 60 * 60 * 1000;

function pruneSamlSeenIds() {
  const now = Date.now();
  for (const [key, expiry] of samlSeenIds) {
    if (now > expiry) samlSeenIds.delete(key);
  }
}

function checkSamlReplay(parsed) {
  pruneSamlSeenIds();
  const now = Date.now();
  const responseIdHash = parsed.responseId ? shortHash(parsed.responseId, 64) : null;
  const assertionIdHash = parsed.assertionId ? shortHash(parsed.assertionId, 64) : null;

  const responseIdSeenBefore = Boolean(responseIdHash && samlSeenIds.has(`r:${responseIdHash}`));
  const assertionIdSeenBefore = Boolean(assertionIdHash && samlSeenIds.has(`a:${assertionIdHash}`));

  if (responseIdSeenBefore || assertionIdSeenBefore) {
    return { result: "replay_detected", response_id_seen_before: responseIdSeenBefore, assertion_id_seen_before: assertionIdSeenBefore };
  }

  // TTL: use NotOnOrAfter + clock skew if available, else default
  let ttlMs = SAML_REPLAY_TTL_MS;
  if (parsed.notOnOrAfter) {
    const noaTime = new Date(parsed.notOnOrAfter).getTime();
    if (Number.isFinite(noaTime) && noaTime > now) {
      ttlMs = Math.min(noaTime - now + SAML_CLOCK_SKEW_SECONDS * 1000, SAML_REPLAY_TTL_MS);
    }
  }

  if (responseIdHash) samlSeenIds.set(`r:${responseIdHash}`, now + ttlMs);
  if (assertionIdHash) samlSeenIds.set(`a:${assertionIdHash}`, now + ttlMs);
  return { result: "valid", response_id_seen_before: false, assertion_id_seen_before: false };
}

function checkRateLimit(sessionId, action, max, windowMs) {
  const key = `${action}:${sessionId}`;
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now >= entry.resetAt) {
    rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= max) return false;
  entry.count++;
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap.entries()) {
    if (now >= entry.resetAt) rateLimitMap.delete(key);
  }
}, 10 * 60 * 1000).unref();

function send(res, statusCode, body, contentType) {
  res.writeHead(statusCode, {
    "content-type": contentType,
    ...SECURITY_HEADERS
  });
  res.end(body);
}

function sendHtml(res, html) {
  send(res, 200, html, "text/html; charset=utf-8");
}

function sendHtmlStatus(res, statusCode, html) {
  send(res, statusCode, html, "text/html; charset=utf-8");
}

function sendJson(res, statusCode, payload) {
  send(res, statusCode, JSON.stringify(payload, null, 2), "application/json; charset=utf-8");
}

function redirect(res, location) {
  res.writeHead(302, {
    location,
    ...SECURITY_HEADERS
  });
  res.end();
}

function routeTab(url) {
  return url.searchParams.get("tab") || null;
}

function firstForwardedValue(value = "") {
  if (Array.isArray(value)) {
    return firstForwardedValue(value[0] || "");
  }

  return String(value).split(",")[0].trim();
}

function resolvePublicBaseUrl(req) {
  if (process.env.BASE_URL?.trim()) {
    return process.env.BASE_URL.trim();
  }

  const forwardedProto = firstForwardedValue(req.headers["x-forwarded-proto"]) || "http";
  const forwardedHost = firstForwardedValue(req.headers["x-forwarded-host"]);
  const host = forwardedHost || firstForwardedValue(req.headers.host);

  if (host) {
    return `${forwardedProto}://${host}`;
  }

  if (RENDER_EXTERNAL_URL) {
    return RENDER_EXTERNAL_URL;
  }

  return `http://localhost:${PORT}`;
}

function currentPath(req) {
  return new URL(req.url, resolvePublicBaseUrl(req));
}

function matchServiceProviderEditPath(pathname) {
  const match = pathname.match(/^\/oidc\/service-providers\/([^/]+)\/edit$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchServiceProviderUpdatePath(pathname) {
  const match = pathname.match(/^\/oidc\/service-providers\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchServiceProviderDeletePath(pathname) {
  const match = pathname.match(/^\/oidc\/service-providers\/([^/]+)\/delete$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowStartPath(pathname) {
  const match = pathname.match(/^\/oidc\/flows\/start\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowResultPath(pathname) {
  const match = pathname.match(/^\/oidc\/flows\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowDetailsPath(pathname) {
  const match = pathname.match(/^\/oidc\/flows\/([^/]+)\/details$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowRerunPath(pathname) {
  const match = pathname.match(/^\/oidc\/flows\/([^/]+)\/rerun$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlServiceProviderEditPath(pathname) {
  const match = pathname.match(/^\/saml\/service-providers\/([^/]+)\/edit$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlServiceProviderUpdatePath(pathname) {
  const match = pathname.match(/^\/saml\/service-providers\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlServiceProviderDeletePath(pathname) {
  const match = pathname.match(/^\/saml\/service-providers\/([^/]+)\/delete$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlFlowStartPath(pathname) {
  const match = pathname.match(/^\/saml\/flows\/start\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlAcsPath(pathname) {
  const match = pathname.match(/^\/saml\/acs\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlFlowResultPath(pathname) {
  const match = pathname.match(/^\/saml\/flows\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchSamlFlowDetailsPath(pathname) {
  const match = pathname.match(/^\/saml\/flows\/([^/]+)\/details$/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function serveStatic(res, asset) {
  const content = await readFile(asset.filePath, "utf8");
  send(res, 200, content, asset.contentType);
}

function evaluateState(expectedState, receivedState) {
  if (!expectedState) {
    return "unknown";
  }

  if (!receivedState) {
    return "missing";
  }

  return expectedState === receivedState ? "match" : "mismatch";
}

function evaluateFlowState(flow, receivedState) {
  const expectedState = flow?.runtime?.expectedState || "";
  if (expectedState) {
    return evaluateState(expectedState, receivedState);
  }

  return lifecycleHashMatches(receivedState, flow?.runtime?.stateSha256 || "") ? "match" : evaluateState("", receivedState);
}

function findRunningFlowByCallbackState(state) {
  const directMatch = flowService.findRunningFlowByState(state || "", FLOW_STATE_TTL_MS);
  if (directMatch) {
    return directMatch;
  }

  if (!state) {
    return null;
  }

  const cutoff = Date.now() - FLOW_STATE_TTL_MS;
  return flowService.listFlows().find((flow) =>
    flow.status === "running" &&
    lifecycleHashMatches(state, flow.runtime?.stateSha256 || "") &&
    new Date(flow.startedAt).getTime() > cutoff
  ) || null;
}

function findSingleRecentRunningOidcFlow() {
  const cutoff = Date.now() - FLOW_STATE_TTL_MS;
  const candidates = flowService.listFlows().filter((flow) =>
    flow.status === "running" &&
    new Date(flow.startedAt).getTime() > cutoff
  );

  return candidates.length === 1 ? candidates[0] : null;
}

function responseHeadersToObject(headers) {
  const result = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function guessNetworkHint(details = {}, requestUrl = "") {
  const code = details.code || "";
  const causeMessage = details.causeMessage || "";
  const hostname = details.hostname || "";
  const lowerUrl = String(requestUrl).toLowerCase();
  const lowerHost = String(hostname).toLowerCase();

  if (lowerHost === "localhost" || lowerHost === "127.0.0.1" || lowerUrl.includes("://localhost") || lowerUrl.includes("://127.0.0.1")) {
    return "The target endpoint uses localhost/127.0.0.1. From Docker, that points to the container itself, not the host or the IdP.";
  }

  if (code === "ENOTFOUND") {
    return "The token endpoint DNS name cannot be resolved from the container.";
  }

  if (code === "ECONNREFUSED") {
    return "The TCP connection was refused. The target service is probably not listening on that host/port.";
  }

  if (code === "ECONNRESET") {
    return "The connection was interrupted by the server or an intermediate device.";
  }

  if (code === "ETIMEDOUT" || causeMessage.toLowerCase().includes("timeout")) {
    return "The endpoint did not respond within the expected timeout. It may be unreachable or filtered.";
  }

  if (causeMessage.toLowerCase().includes("certificate") || causeMessage.toLowerCase().includes("self-signed")) {
    return "The TLS handshake failed. The server certificate is probably not recognized by Node in the container.";
  }

  if (causeMessage.toLowerCase().includes("ssl") || causeMessage.toLowerCase().includes("tls")) {
    return "The TLS handshake failed. Check the certificate, the trust chain and the target https URL.";
  }

  return "Low-level network error before any HTTP response. Check the URL, DNS resolution, network accessibility and TLS.";
}

function formatFetchError(error, request) {
  const cause = error?.cause || null;
  const details = {
    name: error?.name || "Error",
    message: error?.message || "Unknown fetch error.",
    causeName: cause?.name || "",
    causeMessage: cause?.message || "",
    code: cause?.code || error?.code || "",
    errno: cause?.errno || error?.errno || "",
    syscall: cause?.syscall || error?.syscall || "",
    hostname: cause?.hostname || error?.hostname || "",
    host: cause?.host || error?.host || "",
    port: cause?.port || error?.port || "",
    address: cause?.address || error?.address || ""
  };

  const summaryParts = [details.message];
  if (details.code) {
    summaryParts.push(`[${details.code}]`);
  }
  if (details.causeMessage && details.causeMessage !== details.message) {
    summaryParts.push(details.causeMessage);
  }

  return {
    summary: summaryParts.join(" | "),
    details: {
      ...details,
      requestUrl: request?.url || "",
      hint: guessNetworkHint(details, request?.url || "")
    }
  };
}

async function executeHttp(request) {
  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body || undefined,
      redirect: "manual"
    });
    const headers = responseHeadersToObject(response.headers);
    const body = await response.text();
    const parsed = safeJsonParse(body);

    return {
      status: response.status,
      ok: response.ok,
      headers,
      body,
      redactedBody: redactBodyText(body, headers["content-type"] || ""),
      parsed
    };
  } catch (error) {
    const formattedError = formatFetchError(error, request);
    return {
      status: 0,
      ok: false,
      headers: {},
      body: "",
      redactedBody: "",
      parsed: null,
      error: formattedError.summary,
      diagnostics: formattedError.details
    };
  }
}

function buildDiscoveryRequest(discoveryUrl) {
  return {
    url: discoveryUrl,
    method: "GET",
    headers: {
      accept: "application/json"
    },
    params: {},
    body: "",
    redactedBody: "",
    curl: buildCurlCommand({
      url: discoveryUrl,
      method: "GET",
      headers: {
        accept: "application/json"
      }
    })
  };
}

function ensureHtmlSessionRoute(req) {
  return req.headers.accept?.includes("text/html") || req.headers.accept === "*/*" || !req.headers.accept;
}

function selectedClaims(claims = {}) {
  const allowed = ["iss", "sub", "aud", "exp", "iat"];
  return allowed.reduce((acc, key) => {
    if (claims?.[key] !== undefined) {
      acc[key] = claims[key];
    }
    return acc;
  }, {});
}

function tokenReceived(value) {
  return value ? "received" : "missing";
}

function yesNo(value) {
  return value ? "yes" : "no";
}

function epochToIso(value) {
  const numberValue = Number(value);
  if (!Number.isFinite(numberValue)) {
    return "";
  }

  return new Date(numberValue * 1000).toISOString();
}

function buildIdTokenDiagnostics(idToken = "", expectedNonce = "", expectedNonceHash = "") {
  const decoded = decodeJwt(idToken || "");
  if (!idToken) {
    return {
      id_token_received: "no",
      decoded: "no",
      claims_readable: "no",
      signature_validation: "not implemented",
      overall_validation: "incomplete"
    };
  }

  if (!decoded.isJwt) {
    return {
      id_token_received: "yes",
      format: "not JWT",
      decode_error: decoded.error || "JWT could not be decoded.",
      decoded: "no",
      claims_readable: "no",
      nonce_validation: "not checked",
      signature_validation: "not implemented",
      overall_validation: "incomplete"
    };
  }

  const nonceClaim = decoded.payload?.nonce || "";
  const nonceValidation = nonceClaim && expectedNonce
    ? (nonceClaim === expectedNonce ? "valid" : "invalid")
    : nonceClaim && expectedNonceHash
      ? (lifecycleHashMatches(nonceClaim, expectedNonceHash) ? "valid" : "invalid")
      : nonceClaim ? "not checked" : "missing";

  return {
    id_token_received: "yes",
    decoded: "yes",
    claims_readable: "yes",
    jwt_header_alg: decoded.header?.alg || "",
    jwt_header_kid: decoded.header?.kid || "",
    issuer: decoded.payload?.iss || "",
    audience: Array.isArray(decoded.payload?.aud) ? decoded.payload.aud.join(", ") : decoded.payload?.aud || "",
    subject: decoded.payload?.sub || "",
    expiration: epochToIso(decoded.payload?.exp),
    issued_at: epochToIso(decoded.payload?.iat),
    nonce_claim_present: yesNo(nonceClaim),
    nonce_validation: nonceValidation,
    signature_validation: "not implemented",
    overall_validation: "incomplete"
  };
}

function flowStatusLabel(status = "running") {
  if (status === "success") {
    return { label: "Success", tone: "success" };
  }

  if (status === "failed") {
    return { label: "Failed", tone: "error" };
  }

  if (status === "partial_success") {
    return { label: "Partial success", tone: "warning" };
  }

  return { label: "Running", tone: "neutral" };
}

function environmentLabel(environmentKey = "") {
  if (environmentKey === "preprod") {
    return "Preprod";
  }

  if (environmentKey === "prod") {
    return "Prod";
  }

  return "";
}

function stepStatusLabel(status = "pending") {
  if (status === "success") {
    return { label: "Success", tone: "success" };
  }

  if (status === "error") {
    return { label: "Error", tone: "error" };
  }

  if (status === "skipped") {
    return { label: "Skipped", tone: "warning" };
  }

  return { label: "Pending", tone: "neutral" };
}

function samlFlowDetailSummary(flow) {
  if (!flow) return null;
  return {
    id: flow.id,
    serviceProviderId: flow.serviceProviderId,
    status: flow.status,
    statusBadge: flowStatusLabel(flow.status),
    startedAt: flow.startedAt,
    completedAt: flow.completedAt,
    failedStep: flow.failedStep,
    errorCode: flow.errorCode,
    errorDescription: flow.errorDescription,
    durationMs: flow.durationMs,
    runtime: flow.runtime || null,
    environmentLabel: flow.runtime?.environmentLabel || environmentLabel(flow.runtime?.environment)
  };
}

function isLegacySamlPlaceholder(value = "") {
  return /\[(AuthnRequest|SAMLResponse) XML — redacted by default\]/.test(String(value || ""));
}

function redactSamlScalarForUi(key = "", value = "") {
  const text = String(value ?? "");
  const normalizedKey = String(key || "").toLowerCase();
  const sensitiveScalarKeys = new Set([
    "samlrequest",
    "samlresponse",
    "relaystate",
    "signature",
    "signaturevalue",
    "digestvalue",
    "x509certificate",
    "sessionindex",
    "attributevalue"
  ]);
  const isNameIdValue =
    (normalizedKey === "name_id" || normalizedKey === "nameid" || normalizedKey.endsWith("_name_id")) &&
    !normalizedKey.includes("format") &&
    !normalizedKey.includes("hash") &&
    !normalizedKey.includes("preview") &&
    !normalizedKey.includes("present") &&
    !normalizedKey.includes("masked");

  if (isNameIdValue && text) {
    return {
      present: "yes",
      preview: "received / redacted",
      sha256_12: shortHash(text)
    };
  }

  if (sensitiveScalarKeys.has(normalizedKey) && text && !["present", "missing", "received / redacted", "redacted"].includes(text)) {
    return {
      present: "present",
      size_bytes: Buffer.byteLength(text, "utf8"),
      sha256_12: shortHash(text)
    };
  }

  if (isLegacySamlPlaceholder(text)) {
    return "[legacy placeholder: raw XML was not persisted]";
  }

  if (text && /[?&](SAMLRequest|SAMLResponse|RelayState|Signature)=/i.test(text)) {
    return redactSamlRedirectUrl(text);
  }

  if (text.includes("<") && (normalizedKey.includes("xml") || /(?:saml|SignatureValue|DigestValue|X509Certificate|AttributeValue|NameID)/i.test(text))) {
    return redactSamlXml(text);
  }

  if (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(text)) {
    return text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, (match) => `${maskSamlValue(match)} [sha256:${shortHash(match)}]`);
  }

  return value;
}

function sanitizeLegacySamlAttributes(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return sanitizeSamlDiagnosticValue(value, "attribute_value");
  }

  return Object.fromEntries(
    Object.entries(value).map(([attributeName, attributeValue]) => {
      const values = Array.isArray(attributeValue) ? attributeValue : [attributeValue];
      return [
        attributeName,
        {
          values_count: values.length,
          values: values.map((entry) => ({
            present: entry !== null && entry !== undefined && entry !== "" ? "present" : "missing",
            sha256_12: entry ? shortHash(entry) : "",
            redacted: entry ? "received / redacted" : "missing"
          }))
        }
      ];
    })
  );
}

function sanitizeSamlDiagnosticValue(value, key = "") {
  const normalizedKey = String(key || "").toLowerCase();

  if (value === null || value === undefined) {
    return value;
  }

  if (normalizedKey === "attributes") {
    return sanitizeLegacySamlAttributes(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeSamlDiagnosticValue(entry, key));
  }

  if (typeof value === "object") {
    if (Object.keys(value).length === 1 && typeof value.xml === "string" && isLegacySamlPlaceholder(value.xml)) {
      return {
        raw_type: "Legacy placeholder",
        is_real_http_exchange: false,
        note: "This flow was recorded before structured SAML raw diagnostics were persisted.",
        xml: "[not persisted]"
      };
    }

    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entryValue]) => [
        entryKey,
        sanitizeSamlDiagnosticValue(entryValue, entryKey)
      ])
    );
  }

  if (typeof value === "string") {
    return redactSamlScalarForUi(key, value);
  }

  return value;
}

function samlStepSummary(stepName, step) {
  return {
    stepName,
    status: step?.status || "pending",
    badge: stepStatusLabel(step?.status || "pending"),
    httpMethod: step?.httpMethod || "",
    endpoint: step?.endpoint || "",
    httpStatus: step?.httpStatus ?? null,
    requestData: sanitizeSamlDiagnosticValue(step?.requestData || null),
    responseData: sanitizeSamlDiagnosticValue(step?.responseData || null),
    rawRequestData: sanitizeSamlDiagnosticValue(step?.rawRequestData || null),
    rawResponseData: sanitizeSamlDiagnosticValue(step?.rawResponseData || null),
    errorData: sanitizeSamlDiagnosticValue(step?.errorData || null),
    createdAt: step?.createdAt || null,
    completedAt: step?.completedAt || null
  };
}

function buildSamlFlowViewModel(session, flowId, url) {
  const flow = samlFlowService.getFlow(flowId);
  if (!flow) return null;

  const sp = samlServiceProviderService.getSamlServiceProvider(flow.serviceProviderId);
  const steps = samlFlowService.getFlowSteps(flow.id);
  const stepsByName = new Map(steps.map((step) => [step.stepName, step]));
  const selectedStep = SAML_STEP_ORDER.includes(url.searchParams.get("step"))
    ? url.searchParams.get("step")
    : steps.find((step) => step.status === "error")?.stepName || SAML_STEP_ORDER[0];

  return {
    flash: consumeFlash(session),
    flow: samlFlowDetailSummary(flow),
    serviceProvider: sp ? sanitizeSamlServiceProviderForUi(sp) : {
      id: flow.serviceProviderId,
      name: flow.runtime?.serviceProviderName || "Service Provider"
    },
    steps: SAML_STEP_ORDER.map((stepName) => samlStepSummary(stepName, stepsByName.get(stepName))),
    selectedStep
  };
}

function recommendedAction(failedStep = "") {
  if (failedStep === "authorize") {
    return "Authorization request could not be created.";
  }

  if (failedStep === "callback") {
    return "Ez-Access returned an error during callback or the state validation failed.";
  }

  if (failedStep === "token") {
    return "Token exchange failed. Verify the Client ID, Client Secret, Redirect URI and client authentication method.";
  }

  if (failedStep === "userinfo") {
    return "UserInfo request failed. Verify the access token, scopes and UserInfo endpoint availability.";
  }

  return "";
}

function flowSummary(flow) {
  if (!flow) {
    return null;
  }

  return {
    id: flow.id,
    protocol: "OIDC",
    href: `/oidc/flows/${flow.id}`,
    serviceProviderId: flow.serviceProviderId,
    status: flow.status,
    statusBadge: flowStatusLabel(flow.status),
    startedAt: flow.startedAt,
    updatedAt: flow.updatedAt,
    completedAt: flow.completedAt,
    lastStep: flow.lastStep,
    failedStep: flow.failedStep,
    errorCode: flow.errorCode,
    errorDescription: flow.errorDescription,
    durationMs: flow.durationMs,
    serviceProviderName: flow.runtime?.serviceProviderName || "",
    clientId: flow.runtime?.clientId || "",
    environment: flow.runtime?.environment || "",
    environmentLabel: flow.runtime?.environmentLabel || environmentLabel(flow.runtime?.environment),
    runtime: flow.runtime || null
  };
}

function samlFlowSummary(flow) {
  if (!flow) {
    return null;
  }

  return {
    id: flow.id,
    protocol: "SAML",
    href: `/saml/flows/${flow.id}`,
    serviceProviderId: flow.serviceProviderId,
    status: flow.status,
    statusBadge: flowStatusLabel(flow.status),
    startedAt: flow.startedAt,
    completedAt: flow.completedAt,
    serviceProviderName: flow.runtime?.serviceProviderName || "",
    environment: flow.runtime?.environment || "",
    environmentLabel: flow.runtime?.environmentLabel || ""
  };
}

function flowStepSummary(stepName, step) {
  const rawRequestData = step?.rawRequestData
    ? sanitizeOidcRawRequestForStep(stepName, step.rawRequestData, step)
    : null;
  const rawResponseData = step?.rawResponseData
    ? sanitizeOidcRawResponseForStep(stepName, step.rawResponseData, step)
    : null;
  const baseResponseData = step?.responseData?.authorization_url_full
    ? {
        ...step.responseData,
        authorization_url_full: redactDiagnosticUrl(step.responseData.authorization_url_full)
      }
    : step?.responseData || null;
  const responseData = stepName === "token" && rawResponseData
    ? buildTokenResponseSummary(rawResponseData, baseResponseData || {})
    : stepName === "userinfo" && rawResponseData
      ? buildUserInfoResponseSummary(rawResponseData, baseResponseData || {})
      : baseResponseData;

  return {
    stepName,
    status: step?.status || "pending",
    badge: stepStatusLabel(step?.status || "pending"),
    httpMethod: step?.httpMethod || "",
    endpoint: step?.endpoint || "",
    httpStatus: step?.httpStatus ?? null,
    requestData: step?.requestData || null,
    responseData,
    rawRequestData,
    rawResponseData,
    rawAnalysisData: step?.rawAnalysisData ? sanitizeDiagnosticData(step.rawAnalysisData) : null,
    rawRequestNature: step?.rawRequestNature || "",
    rawResponseNature: step?.rawResponseNature || "",
    errorData: step?.errorData || null,
    createdAt: step?.createdAt || null,
    completedAt: step?.completedAt || null
  };
}

function listValue(values = []) {
  return Array.isArray(values) && values.length > 0 ? values.join(", ") : "";
}

function tokenAuthMethodForServiceProviders(serviceProviders = [], environmentKey = "", fallback = "") {
  const matching = serviceProviders.filter((serviceProvider) => serviceProvider.environment === environmentKey);
  const source = matching.length > 0 ? matching : serviceProviders;
  const methods = new Set(
    source
      .map((serviceProvider) => (serviceProvider.clientType === "confidential" ? "client_secret_basic" : "none"))
      .filter(Boolean)
  );

  if (methods.size === 1) {
    return Array.from(methods)[0];
  }

  if (methods.size > 1) {
    return "Depends on Service Provider";
  }

  return fallback || "";
}

function buildOidcPageConfiguration() {
  return {
    redirectUri: sanitizeProviderConfig(providerConfig).redirectUri,
    environments: listEzAccessEnvironments().map((environment) => {
      const envConfig = oidcEnvironmentConfig[environment.key] || {};
      const metadataAvailable = Boolean(
        envConfig.issuer || envConfig.authorizationEndpoint || envConfig.tokenEndpoint || envConfig.jwksUri
      );

      return {
        key: environment.key,
        label: environmentLabel(environment.key) || environment.label || environment.key,
        discoveryUrl: envConfig.discoveryUrl || environment.discoveryUrl || "",
        discoveredAt: envConfig.discoveredAt || null,
        metadataAvailable,
        issuer: envConfig.issuer || "",
        authorizationEndpoint: envConfig.authorizationEndpoint || "",
        tokenEndpoint: envConfig.tokenEndpoint || "",
        userInfoEndpoint: envConfig.userInfoEndpoint || "",
        jwksUri: envConfig.jwksUri || "",
        scopesSupported: Array.isArray(envConfig.scopesSupported) ? envConfig.scopesSupported : [],
        responseTypesSupported: Array.isArray(envConfig.responseTypesSupported) ? envConfig.responseTypesSupported : [],
        tokenEndpointAuthMethodsSupported: Array.isArray(envConfig.tokenEndpointAuthMethodsSupported) ? envConfig.tokenEndpointAuthMethodsSupported : [],
        pkceEnabled: "yes",
        pkceMethod: "S256",
        responseType: "code",
        grantType: "authorization_code",
        userInfoEnabled: "yes"
      };
    })
  };
}

function buildFlowViewModel(session, flowId, url) {
  const flow = flowService.getFlow(flowId);
  if (!flow) {
    return null;
  }

  const serviceProvider = getServiceProvider(flow.serviceProviderId);
  const steps = flowService.getFlowSteps(flow.id);
  const stepsByName = new Map(steps.map((step) => [step.stepName, step]));
  const selectedStep = STEP_ORDER.includes(url.searchParams.get("step"))
    ? url.searchParams.get("step")
    : steps.find((step) => step.status === "error")?.stepName || "authorize";

  return {
    flash: consumeFlash(session),
    flow: flowSummary(flow),
    flowRaw: flow,
    serviceProvider: sanitizeServiceProviderForUi(serviceProvider) || {
      id: flow.serviceProviderId,
      name: flow.runtime?.serviceProviderName || "Service Provider",
      environment: flow.runtime?.environment || "",
      environmentLabel: flow.runtime?.environmentLabel || environmentLabel(flow.runtime?.environment),
      clientId: flow.runtime?.clientId || "",
      scopes: flow.runtime?.scopes || ""
    },
    steps: STEP_ORDER.map((stepName) => flowStepSummary(stepName, stepsByName.get(stepName))),
    selectedStep,
    recommendedAction: recommendedAction(flow.failedStep)
  };
}

function attachFlowsToServiceProviders(entries) {
  return entries.map((serviceProvider) => {
    const lastFlow = flowSummary(flowService.getLastFlowForServiceProvider(serviceProvider.id));

    return {
      ...serviceProvider,
      lastFlow
    };
  });
}

function attachSamlFlowsToServiceProviders(entries) {
  return entries.map((serviceProvider) => ({
    ...serviceProvider,
    lastFlow: samlFlowSummary(samlFlowService.getLastFlowForServiceProvider(serviceProvider.id))
  }));
}

function buildAuthorizeStep({ flow, runConfig, prepared }) {
  const rawRequestData = sanitizeAuthorizationRequestRaw(prepared.request);

  return {
    stepName: "authorize",
    status: "success",
    httpMethod: "GET",
    endpoint: runConfig.config.authorizationEndpoint,
    httpStatus: 302,
    requestData: {
      method: "GET",
      http_mode: "browser redirect",
      endpoint: runConfig.config.authorizationEndpoint,
      environment: flow.runtime?.environmentLabel || "",
      client_id: runConfig.config.clientId,
      redirect_uri: runConfig.config.redirectUri,
      scope: runConfig.config.scopes,
      response_type: runConfig.config.responseType,
      state: prepared.runtime.state ? "generated + sent" : "missing",
      nonce: prepared.runtime.nonce ? "generated + sent" : "missing",
      pkce: prepared.runtime.codeChallenge ? `${prepared.config.codeChallengeMethod || "S256"} challenge sent` : "disabled",
      code_challenge: prepared.runtime.codeChallenge ? "sent" : "missing"
    },
    responseData: {
      redirect_to: "Ez-Access",
      authorization_url: "prepared + redacted in raw",
      authorization_url_redacted: rawRequestData?.url || "",
      flow_id: flow.id
    },
    rawRequestData,
    rawResponseData: sanitizeRawResponse({
      status: 302,
      ok: true,
      headers: {
        location: "Ez-Access authorize redirect"
      },
      parsed: {
        redirect_to: "Ez-Access",
        authorization_url: "present"
      }
    }),
    rawRequestNature: "Prepared browser redirect",
    rawResponseNature: "Synthetic local response",
    completedAt: new Date().toISOString()
  };
}

function validateDiscoveryUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") {
    return "Discovery URL is required.";
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return "Discovery URL is not a valid URL.";
  }

  if (parsed.protocol === "https:") {
    return null;
  }

  if (parsed.protocol === "http:") {
    const host = parsed.hostname.toLowerCase();
    if (NODE_ENV === "development" && (host === "localhost" || host === "127.0.0.1")) {
      return null;
    }
    return "Discovery URL must use HTTPS.";
  }

  return `Unsupported protocol: ${parsed.protocol} Only https:// is accepted.`;
}

async function importDiscoveryMetadata(discoveryUrl) {
  const MAX_RESPONSE_BYTES = 256 * 1024;
  const TIMEOUT_MS = 6000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(discoveryUrl, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal,
      redirect: "follow"
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return { ok: false, error: `Discovery endpoint returned HTTP ${response.status}.` };
    }

    const contentLength = Number(response.headers.get("content-length") || 0);
    if (contentLength > MAX_RESPONSE_BYTES) {
      return { ok: false, error: "Discovery response is too large." };
    }

    const text = await response.text();
    if (text.length > MAX_RESPONSE_BYTES) {
      return { ok: false, error: "Discovery response is too large." };
    }

    let doc;
    try {
      doc = JSON.parse(text);
    } catch {
      return { ok: false, error: "Discovery endpoint did not return valid JSON." };
    }

    if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
      return { ok: false, error: "Discovery document has an unexpected structure." };
    }

    const metadata = {
      issuer: typeof doc.issuer === "string" ? doc.issuer : "",
      authorizationEndpoint: typeof doc.authorization_endpoint === "string" ? doc.authorization_endpoint : "",
      tokenEndpoint: typeof doc.token_endpoint === "string" ? doc.token_endpoint : "",
      userInfoEndpoint: typeof doc.userinfo_endpoint === "string" ? doc.userinfo_endpoint : "",
      jwksUri: typeof doc.jwks_uri === "string" ? doc.jwks_uri : "",
      scopesSupported: Array.isArray(doc.scopes_supported) ? doc.scopes_supported.filter((s) => typeof s === "string") : [],
      responseTypesSupported: Array.isArray(doc.response_types_supported) ? doc.response_types_supported.filter((s) => typeof s === "string") : [],
      tokenEndpointAuthMethodsSupported: Array.isArray(doc.token_endpoint_auth_methods_supported) ? doc.token_endpoint_auth_methods_supported.filter((s) => typeof s === "string") : []
    };

    if (!metadata.issuer && !metadata.authorizationEndpoint && !metadata.tokenEndpoint) {
      return { ok: false, error: "Discovery document is missing required fields (issuer, authorization_endpoint, token_endpoint)." };
    }

    return { ok: true, metadata };
  } catch (error) {
    clearTimeout(timeoutId);

    if (error.name === "AbortError") {
      return { ok: false, error: "Discovery request timed out." };
    }

    return { ok: false, error: "Could not reach the Discovery endpoint." };
  }
}

async function resolveEzAccessProviderConfig(environmentKey) {
  const environment = getEzAccessEnvironment(environmentKey);

  if (!environment) {
    throw new Error("Ez-Access environment is invalid.");
  }

  if (!environment.discoveryUrl) {
    throw new Error(`Ez-Access ${environmentLabel(environment.key) || environment.key} Discovery URL is not configured.`);
  }

  const requestSnapshot = buildDiscoveryRequest(environment.discoveryUrl);
  const responseSnapshot = await executeHttp(requestSnapshot);

  if (!responseSnapshot.ok || Object.keys(responseSnapshot.parsed || {}).length === 0) {
    throw new Error(
      responseSnapshot.error
        ? `Ez-Access ${environmentLabel(environment.key)} discovery failed: ${responseSnapshot.error}`
        : `Ez-Access ${environmentLabel(environment.key)} discovery returned ${responseSnapshot.status || "an unknown error"}.`
    );
  }

  return {
    environment,
    provider: mergeDiscoveryIntoProviderConfig(
      {
        ...createProviderConfig(),
        providerName: environment.label,
        discoveryUrl: ""
      },
      responseSnapshot.parsed
    )
  };
}

function buildCallbackStep({ flow, req, params, stateCheck }) {
  const hasError = Boolean(params.error);
  const success = !hasError && stateCheck === "match" && Boolean(params.code);

  return {
    stepName: "callback",
    status: success ? "success" : "error",
    httpMethod: req.method,
    endpoint: "/oidc/callback",
    httpStatus: 302,
    requestData: {
      redirect_uri: flow.runtime?.redirectUri || "",
      callback_method: req.method,
      callback_path: "/oidc/callback",
      expected_parameters: "code, state",
      expected_state: "present"
    },
    responseData: {
      authorization_code: params.code ? "received" : "missing",
      state: params.state ? "received" : "missing",
      state_validation: stateCheck === "match" ? "valid" : stateCheck,
      provider_error: params.error ? "received" : "none",
      error: params.error || "",
      error_description: params.error_description || ""
    },
    rawRequestData: sanitizeCallbackRaw({ req, params, stateCheck }),
    rawResponseData: sanitizeCallbackRaw({ req, params, stateCheck }),
    rawRequestNature: "Reconstructed inbound request",
    rawResponseNature: "Callback received",
    errorData: success
      ? null
      : {
          errorCode: params.error || (stateCheck === "match" ? "missing_code" : "state_validation_failed"),
          errorDescription:
            params.error_description ||
            (stateCheck === "match" ? "Callback did not contain an authorization code." : "Callback state did not match the expected flow state.")
        },
    completedAt: new Date().toISOString()
  };
}

function buildTokenStep({ requestSnapshot, responseSnapshot, flow = null }) {
  const parsed = responseSnapshot.parsed || {};
  const idTokenClaims = decodeJwt(parsed.id_token || "");
  const accessTokenClaims = decodeJwt(parsed.access_token || "");
  const ok = Boolean(responseSnapshot.ok && !parsed.error && !responseSnapshot.error);
  const authHeader = requestSnapshot.headers?.authorization || "";
  const clientAuthenticationMethod = /^basic\s+/i.test(authHeader) ? "client_secret_basic" : "none";
  const rawResponseData = sanitizeTokenResponseRaw(responseSnapshot);

  return {
    stepName: "token",
    status: ok ? "success" : "error",
    httpMethod: "POST",
    endpoint: requestSnapshot.url,
    httpStatus: responseSnapshot.status || 0,
    requestData: {
      method: "POST",
      endpoint: requestSnapshot.url,
      grant_type: "authorization_code",
      client_authentication_method: clientAuthenticationMethod,
      client_id: requestSnapshot.params?.client_id || "sent via Authorization header",
      client_secret_used: clientAuthenticationMethod === "client_secret_basic" ? "yes, masked" : "no",
      redirect_uri: requestSnapshot.params?.redirect_uri || "",
      authorization_code: requestSnapshot.params?.code ? "received + sent, masked" : "missing",
      code_verifier: requestSnapshot.params?.code_verifier ? "sent" : "not sent"
    },
    responseData: {
      ...buildTokenResponseSummary(rawResponseData),
      token_error: parsed.error || responseSnapshot.error || "none",
      error_description: parsed.error_description || "",
      id_token_claims: idTokenClaims.isJwt ? selectedClaims(idTokenClaims.payload) : {},
      access_token_claims: accessTokenClaims.isJwt ? selectedClaims(accessTokenClaims.payload) : {},
      id_token_diagnostics: buildIdTokenDiagnostics(parsed.id_token || "", flow?.runtime?.expectedNonce || "", flow?.runtime?.nonceSha256 || "")
    },
    rawRequestData: sanitizeTokenRequestRaw(requestSnapshot),
    rawResponseData,
    rawAnalysisData: buildIdTokenAnalysisRaw(parsed.id_token || "", flow),
    rawRequestNature: "Real outbound HTTP request",
    rawResponseNature: "Real inbound HTTP response",
    errorData: ok
      ? null
      : {
          errorCode: sanitizeDiagnosticError(parsed.error || responseSnapshot.error || "token_exchange_failed"),
          errorDescription: sanitizeDiagnosticError(parsed.error_description || responseSnapshot.error || "Token endpoint did not return usable tokens."),
          diagnostics: responseSnapshot.diagnostics || null
        },
    completedAt: new Date().toISOString()
  };
}

function buildUserInfoStep({ requestSnapshot = null, responseSnapshot = null, skippedReason = "" }) {
  if (skippedReason) {
    return {
      stepName: "userinfo",
      status: "skipped",
      httpMethod: "GET",
      endpoint: requestSnapshot?.url || "",
      httpStatus: null,
      requestData: {
        method: "GET",
        endpoint: requestSnapshot?.url || "",
        called: "no",
        Authorization: "Bearer ********"
      },
      responseData: {
        called: "no",
        skipped_reason: skippedReason
      },
      rawRequestData: sanitizeUserInfoRequestRaw(requestSnapshot),
      rawResponseData: null,
      rawRequestNature: requestSnapshot ? "Real outbound HTTP request" : "Skipped",
      rawResponseNature: "Skipped",
      errorData: null,
      completedAt: new Date().toISOString()
    };
  }

  const parsed = responseSnapshot.parsed || {};
  const rawResponseData = sanitizeUserInfoResponseRaw(responseSnapshot);

  return {
    stepName: "userinfo",
    status: responseSnapshot.ok ? "success" : "error",
    httpMethod: "GET",
    endpoint: requestSnapshot.url,
    httpStatus: responseSnapshot.status || 0,
    requestData: {
      method: "GET",
      endpoint: requestSnapshot.url,
      called: "yes",
      Authorization: "Bearer ********"
    },
    responseData: {
      ...buildUserInfoResponseSummary(rawResponseData, {
        called: "yes",
        subject: parsed.sub || "",
        raw_claims_available: Object.keys(parsed || {}).length > 0 ? "yes" : "no"
      }),
      error: parsed.error || responseSnapshot.error || "none",
      error_description: parsed.error_description || ""
    },
    rawRequestData: sanitizeUserInfoRequestRaw(requestSnapshot),
    rawResponseData,
    rawRequestNature: "Real outbound HTTP request",
    rawResponseNature: "Real inbound HTTP response",
    errorData: responseSnapshot.ok
      ? null
      : {
          errorCode: sanitizeDiagnosticError(parsed.error || responseSnapshot.error || "userinfo_failed"),
          errorDescription: sanitizeDiagnosticError(parsed.error_description || responseSnapshot.error || "UserInfo endpoint did not return a successful response."),
          diagnostics: responseSnapshot.diagnostics || null
        },
    completedAt: new Date().toISOString()
  };
}

function failFlow(flowId, failedStep, errorCode, errorDescription) {
  return completeOidcFlow(flowId, {
    status: "failed",
    lastStep: failedStep,
    failedStep,
    errorCode: errorCode || `${failedStep}_failed`,
    errorDescription: errorDescription || recommendedAction(failedStep)
  });
}

function completeOidcFlow(flowId, patch = {}) {
  const flow = flowService.getFlow(flowId);
  return flowService.completeFlow(flowId, {
    ...patch,
    runtime: sanitizeTerminalOidcRuntime({
      ...(flow?.runtime || {}),
      ...(patch.runtime || {})
    })
  });
}

async function startNewUiFlow(session, serviceProviderId) {
  const selected = getServiceProvider(serviceProviderId);
  if (!selected) {
    return { ok: false, notFound: true };
  }

  const flow = flowService.createFlow(selected.id, {
    serviceProviderName: selected.name,
    environment: selected.environment || "",
    environmentLabel: environmentLabel(selected.environment),
    clientId: selected.clientId,
    scopes: selected.scopes
  });

  if (!isServiceProviderReady(selected)) {
    failFlow(flow.id, "authorize", "service_provider_incomplete", "Service Provider is incomplete. Verify name, Client ID, Client Secret and scopes.");
    flowService.addFlowStep(flow.id, {
      stepName: "authorize",
      status: "error",
      httpMethod: "GET",
      endpoint: "",
      requestData: {
        service_provider: selected.name || selected.clientId || selected.id
      },
      responseData: null,
      rawRequestData: null,
      rawResponseData: null,
      rawRequestNature: "Skipped",
      rawResponseNature: "Skipped",
      errorData: {
        errorCode: "service_provider_incomplete",
        errorDescription: "Service Provider is incomplete. Verify name, Client ID, Client Secret and scopes."
      },
      completedAt: new Date().toISOString()
    });
    return { ok: false, flow };
  }

  try {
    session.selectedServiceProviderId = selected.id;
    const clientSecret = selected.clientType === "confidential" ? decryptSecret(selected.secretRecord) : "";
    const { environment, provider } = await resolveEzAccessProviderConfig(selected.environment);
    const effectiveRedirectUri = provider.redirectUri || FIXED_REDIRECT_URI;
    const runConfig = {
      selected,
      provider,
      config: buildEffectiveConfig({
        providerConfig: provider,
        serviceProvider: selected,
        clientSecret,
        redirectUri: effectiveRedirectUri
      })
    };
    const prepared = prepareAuthorizationRequest(runConfig.config);
    const runtime = {
      serviceProviderName: runConfig.selected.name,
      environment: environment.key,
      environmentLabel: environmentLabel(environment.key),
      clientId: runConfig.selected.clientId,
      scopes: runConfig.selected.scopes,
      provider: {
        providerName: runConfig.provider.providerName,
        issuer: runConfig.provider.issuer,
        authorizationEndpoint: runConfig.provider.authorizationEndpoint,
        tokenEndpoint: runConfig.provider.tokenEndpoint,
        userInfoEndpoint: runConfig.provider.userInfoEndpoint,
        jwksUri: runConfig.provider.jwksUri,
        redirectUri: runConfig.provider.redirectUri,
        scopesSupported: runConfig.provider.scopesSupported || [],
        responseTypesSupported: runConfig.provider.responseTypesSupported || [],
        tokenEndpointAuthMethodsSupported: runConfig.provider.tokenEndpointAuthMethodsSupported || []
      },
      authorizationEndpoint: runConfig.config.authorizationEndpoint,
      tokenEndpoint: runConfig.config.tokenEndpoint,
      userInfoEndpoint: runConfig.config.userInfoEndpoint,
      redirectUri: runConfig.config.redirectUri,
      tokenEndpointAuthMethod: prepared.config.tokenEndpointAuthMethod,
      expectedState: prepared.runtime.state,
      expectedNonce: prepared.runtime.nonce,
      stateSha256: lifecycleHash(prepared.runtime.state),
      nonceSha256: lifecycleHash(prepared.runtime.nonce),
      codeVerifier: prepared.runtime.codeVerifier,
      codeChallenge: prepared.runtime.codeChallenge
    };

    const updatedFlow = flowService.updateFlow(flow.id, { runtime });
    flowService.addFlowStep(flow.id, buildAuthorizeStep({ flow: updatedFlow, runConfig, prepared }));
    return {
      ok: true,
      flow: flowService.getFlow(flow.id),
      authorizationUrl: prepared.request.url
    };
  } catch (error) {
    failFlow(flow.id, "authorize", "authorize_request_failed", error.message);
    flowService.addFlowStep(flow.id, {
      stepName: "authorize",
      status: "error",
      httpMethod: "GET",
      endpoint: providerConfig.authorizationEndpoint || "",
      requestData: {
        service_provider: selected.name || selected.clientId || selected.id
      },
      responseData: null,
      rawRequestData: null,
      rawResponseData: null,
      rawRequestNature: "Skipped",
      rawResponseNature: "Skipped",
      errorData: {
        errorCode: "authorize_request_failed",
        errorDescription: error.message
      },
      completedAt: new Date().toISOString()
    });
    return { ok: false, flow: flowService.getFlow(flow.id) };
  }
}

async function processNewUiCallback({ req, flow, params }) {
  const stateCheck = evaluateFlowState(flow, params.state);
  const callbackStep = buildCallbackStep({ flow, req, params, stateCheck });
  flowService.addFlowStep(flow.id, callbackStep);

  if (callbackStep.status === "error") {
    const errorData = callbackStep.errorData || {};
    failFlow(flow.id, "callback", errorData.errorCode, errorData.errorDescription);
    return flowService.getFlow(flow.id);
  }

  const selected = getServiceProvider(flow.serviceProviderId);
  if (!selected) {
    failFlow(flow.id, "token", "service_provider_missing", "Service Provider no longer exists.");
    return flowService.getFlow(flow.id);
  }

  try {
    const clientSecret = selected.clientType === "confidential" ? decryptSecret(selected.secretRecord) : "";
    const effectiveConfig = buildEffectiveConfig({
      providerConfig: flow.runtime?.provider || providerConfig,
      serviceProvider: selected,
      clientSecret,
      redirectUri: flow.runtime?.redirectUri || FIXED_REDIRECT_URI
    });

    if (effectiveConfig.pkceEnabled !== false && flow.runtime?.codeVerifierPresent === "yes" && !flow.runtime?.codeVerifier) {
      flowService.addFlowStep(flow.id, {
        stepName: "token",
        status: "error",
        httpMethod: "POST",
        endpoint: flow.runtime?.tokenEndpoint || effectiveConfig.tokenEndpoint || "",
        httpStatus: null,
        requestData: {
          method: "POST",
          endpoint: flow.runtime?.tokenEndpoint || effectiveConfig.tokenEndpoint || "",
          client_id: selected.clientId,
          client_secret: selected.clientType === "confidential" ? "********" : "not used",
          code: params.code ? "present" : "missing",
          code_verifier: "missing"
        },
        responseData: null,
        rawRequestData: null,
        rawResponseData: {
          status: 0,
          ok: false,
          headers: {},
          body: {},
          error: "PKCE verifier is no longer available for this running flow."
        },
        rawRequestNature: "Skipped",
        rawResponseNature: "Synthetic local response",
        errorData: {
          errorCode: "pkce_verifier_missing",
          errorDescription: "The running flow lost its PKCE verifier before callback processing. Start a new flow."
        },
        completedAt: new Date().toISOString()
      });
      failFlow(flow.id, "token", "pkce_verifier_missing", "The running flow lost its PKCE verifier before callback processing. Start a new flow.");
      return flowService.getFlow(flow.id);
    }

    const requestSnapshot = buildTokenExchangeRequest({
      config: effectiveConfig,
      code: params.code,
      codeVerifier: flow.runtime?.codeVerifier || ""
    });
    const responseSnapshot = await executeHttp(requestSnapshot);
    const tokenStep = buildTokenStep({ requestSnapshot, responseSnapshot, flow });
    flowService.addFlowStep(flow.id, tokenStep);

    if (tokenStep.status === "error") {
      const errorData = tokenStep.errorData || {};
      failFlow(flow.id, "token", errorData.errorCode, errorData.errorDescription);
      return flowService.getFlow(flow.id);
    }

    const accessToken = responseSnapshot.parsed?.access_token || "";
    const userInfoEndpoint = effectiveConfig.userInfoEndpoint || "";

    if (!accessToken || !userInfoEndpoint) {
      const skippedReason = !accessToken ? "access_token missing" : "UserInfo endpoint missing";
      flowService.addFlowStep(flow.id, buildUserInfoStep({ skippedReason }));
      completeOidcFlow(flow.id, {
        status: "success",
        lastStep: "userinfo",
        failedStep: "",
        errorCode: "",
        errorDescription: ""
      });
      return flowService.getFlow(flow.id);
    }

    const userInfoRequest = buildUserInfoRequest({
      endpoint: userInfoEndpoint,
      accessToken
    });
    const userInfoResponse = await executeHttp(userInfoRequest);
    const userInfoStep = buildUserInfoStep({
      requestSnapshot: userInfoRequest,
      responseSnapshot: userInfoResponse
    });
    flowService.addFlowStep(flow.id, userInfoStep);

    if (userInfoStep.status === "error") {
      const errorData = userInfoStep.errorData || {};
      failFlow(flow.id, "userinfo", errorData.errorCode, errorData.errorDescription);
      return flowService.getFlow(flow.id);
    }

    completeOidcFlow(flow.id, {
      status: "success",
      lastStep: "userinfo",
      failedStep: "",
      errorCode: "",
      errorDescription: ""
    });
    return flowService.getFlow(flow.id);
  } catch (error) {
    flowService.addFlowStep(flow.id, {
      stepName: "token",
      status: "error",
      httpMethod: "POST",
      endpoint: flow.runtime?.tokenEndpoint || "",
      requestData: {
        method: "POST",
        endpoint: flow.runtime?.tokenEndpoint || "",
        client_id: selected.clientId,
        client_secret: "********",
        code: params.code ? "present" : "missing",
        code_verifier: flow.runtime?.codeVerifier ? "present" : "missing"
      },
      responseData: null,
      rawRequestData: sanitizeDiagnosticData({
        method: "POST",
        url: flow.runtime?.tokenEndpoint || "",
        headers: {},
        body: {
          grant_type: "authorization_code",
          code: params.code ? "present" : "missing",
          redirect_uri: flow.runtime?.redirectUri || "",
          code_verifier: flow.runtime?.codeVerifier ? "present" : "missing"
        }
      }),
      rawResponseData: {
        status: 0,
        ok: false,
        headers: {},
        body: {},
        error: sanitizeDiagnosticError(error.message)
      },
      rawRequestNature: "Skipped",
      rawResponseNature: "Synthetic local response",
      errorData: {
        errorCode: "token_exchange_failed",
        errorDescription: error.message
      },
      completedAt: new Date().toISOString()
    });
    failFlow(flow.id, "token", "token_exchange_failed", error.message);
    return flowService.getFlow(flow.id);
  }
}

function buildPageModel(session, activeTab, url) {
  const editServiceProviderId = url.searchParams.get("edit") || "";
  const editingServiceProvider = sanitizeServiceProviderForUi(getServiceProvider(editServiceProviderId));
  const selectedServiceProvider = sanitizeServiceProviderForUi(getServiceProvider(session.selectedServiceProviderId));
  const sanitizedProviderConfig = sanitizeProviderConfig(providerConfig);
  const sanitizedServiceProviders = serviceProviderService.listServiceProviders().map(sanitizeServiceProviderForUi);

  return {
    session,
    activeTab,
    flash: consumeFlash(session),
    providerConfig: sanitizedProviderConfig,
    oidcPageConfiguration: buildOidcPageConfiguration(),
    serviceProviders: attachFlowsToServiceProviders(sanitizedServiceProviders),
    recentFlows: flowService.listRecentFlows(5).map(flowSummary),
    samlRecentFlows: samlFlowService.listRecentFlows(5).map(samlFlowSummary),
    ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi),
    editingServiceProvider,
    selectedServiceProvider,
    fixedRedirectUri: sanitizedProviderConfig.redirectUri
  };
}

const server = http.createServer(async (req, res) => {
  const url = currentPath(req);

  try {
    if (staticFiles.has(url.pathname)) {
      await serveStatic(res, staticFiles.get(url.pathname));
      return;
    }

    if (req.method === "GET" && url.pathname.startsWith("/assets/icons/") && url.pathname.endsWith(".svg")) {
      const iconName = path.basename(url.pathname);
      if (/^[a-z-]+\.svg$/.test(iconName)) {
        try {
          const iconPath = path.join(projectRoot, "public", "assets", "icons", iconName);
          const content = await readFile(iconPath, "utf8");
          send(res, 200, content, "image/svg+xml");
          return;
        } catch {
          // fall through to 404
        }
      }
    }

    if (req.method === "GET" && url.pathname === "/") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, routeTab(url) || "dashboard", url);
      sendHtml(res, renderDashboard(model));
      return;
    }

    if (req.method === "GET" && url.pathname === "/oidc/service-providers") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "service-providers", url);
      sendHtml(res, renderServiceProvidersPage(model));
      return;
    }

    if (req.method === "GET" && url.pathname === "/oidc/service-providers/new") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "service-providers", url);
      sendHtml(res, renderServiceProviderNewPage(model));
      return;
    }

    if (req.method === "POST" && url.pathname === "/oidc/service-providers") {
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "sp-create", 20, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return;
      }
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const result = serviceProviderService.createServiceProvider(body);

      if (!result.ok) {
        const model = {
          ...buildPageModel(session, "service-providers", url),
          form: result.validation
        };
        sendHtml(res, renderServiceProviderNewPage(model));
        return;
      }

      session.selectedServiceProviderId = result.serviceProvider.id;
      touchSession(session);
      addSessionLog(session, "info", "service_provider_created", "Service Provider created.", {
        serviceProvider: sanitizeServiceProviderForUi(result.serviceProvider)
      });
      setFlash(
        session,
        result.validation.warnings.length ? "warn" : "info",
        result.validation.warnings.length
          ? `Service Provider created. ${result.validation.warnings.join(" ")}`
          : "Service Provider created."
      );
      redirect(res, "/oidc/service-providers");
      return;
    }

    const editServiceProviderId = req.method === "GET" ? matchServiceProviderEditPath(url.pathname) : null;
    if (editServiceProviderId) {
      const session = getOrCreateSession(req, res);
      const serviceProvider = getServiceProvider(editServiceProviderId);

      if (!serviceProvider) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      const model = {
        ...buildPageModel(session, "service-providers", url),
        serviceProvider: sanitizeServiceProviderForUi(serviceProvider)
      };
      sendHtml(res, renderServiceProviderEditPage(model));
      return;
    }

    const deleteServiceProviderId = req.method === "POST" ? matchServiceProviderDeletePath(url.pathname) : null;
    if (deleteServiceProviderId) {
      const session = getOrCreateSession(req, res);

      if (!removeServiceProvider(deleteServiceProviderId)) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      addSessionLog(session, "info", "service_provider_deleted", "Service Provider deleted.", {
        serviceProviderId: deleteServiceProviderId
      });
      setFlash(session, "info", "Service Provider deleted.");
      redirect(res, "/oidc/service-providers");
      return;
    }

    const updateServiceProviderId = req.method === "POST" ? matchServiceProviderUpdatePath(url.pathname) : null;
    if (updateServiceProviderId && !["save", "delete", "select", "test"].includes(updateServiceProviderId)) {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const result = serviceProviderService.updateServiceProvider(updateServiceProviderId, body);

      if (result.notFound) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      if (!result.ok) {
        const model = {
          ...buildPageModel(session, "service-providers", url),
          serviceProvider: sanitizeServiceProviderForUi(result.serviceProvider),
          form: result.validation
        };
        sendHtml(res, renderServiceProviderEditPage(model));
        return;
      }

      if (session.selectedServiceProviderId === result.serviceProvider.id) {
        resetFlowState(session, "service_provider_update");
      } else {
        touchSession(session);
      }

      addSessionLog(session, "info", "service_provider_updated", "Service Provider updated.", {
        serviceProvider: sanitizeServiceProviderForUi(result.serviceProvider),
        secretUpdated: result.secretUpdated
      });
      setFlash(
        session,
        result.validation.warnings.length ? "warn" : "info",
        result.validation.warnings.length
          ? `Service Provider updated. ${result.validation.warnings.join(" ")}`
          : result.secretUpdated
            ? "Service Provider updated. The secret was replaced."
            : "Service Provider updated."
      );
      redirect(res, "/oidc/service-providers");
      return;
    }

    const startFlowServiceProviderId = (req.method === "POST" || req.method === "GET") ? matchFlowStartPath(url.pathname) : null;
    if (startFlowServiceProviderId) {
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "flow-start", 10, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return;
      }
      const result = await startNewUiFlow(session, startFlowServiceProviderId);

      if (result.notFound) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      if (!result.ok) {
        redirect(res, `/oidc/flows/${encodeURIComponent(result.flow.id)}`);
        return;
      }

      redirect(res, result.authorizationUrl);
      return;
    }

    const rerunFlowId = req.method === "POST" ? matchFlowRerunPath(url.pathname) : null;
    if (rerunFlowId) {
      const session = getOrCreateSession(req, res);
      const flow = flowService.getFlow(rerunFlowId);

      if (!flow) {
        setFlash(session, "warn", "Flow not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      const result = await startNewUiFlow(session, flow.serviceProviderId);
      if (!result.ok) {
        redirect(res, result.flow ? `/oidc/flows/${encodeURIComponent(result.flow.id)}` : "/oidc/service-providers");
        return;
      }

      redirect(res, result.authorizationUrl);
      return;
    }

    const flowDetailsId = req.method === "GET" ? matchFlowDetailsPath(url.pathname) : null;
    if (flowDetailsId) {
      const session = getOrCreateSession(req, res);
      const model = buildFlowViewModel(session, flowDetailsId, url);

      if (!model) {
        setFlash(session, "warn", "Flow not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      sendHtml(res, renderFlowDetailsPage(model));
      return;
    }

    const flowResultId = req.method === "GET" ? matchFlowResultPath(url.pathname) : null;
    if (flowResultId) {
      const session = getOrCreateSession(req, res);
      const model = buildFlowViewModel(session, flowResultId, url);

      if (!model) {
        setFlash(session, "warn", "Flow not found.");
        redirect(res, "/oidc/service-providers");
        return;
      }

      sendHtml(res, renderFlowResultPage(model));
      return;
    }

    const discoveryImportMatch = req.method === "POST" && url.pathname.match(/^\/oidc\/discovery\/import\/(preprod|prod)$/);
    if (discoveryImportMatch) {
      const session = getOrCreateSession(req, res);
      const environmentKey = discoveryImportMatch[1];

      if (!checkRateLimit(session.id, `discovery-import-${environmentKey}`, 10, 60 * 1000)) {
        sendJson(res, 429, { ok: false, error: "Too many requests. Please wait before retrying." });
        return;
      }

      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const rawDiscoveryUrl = String(body?.discoveryUrl || "").trim();

      const urlError = validateDiscoveryUrl(rawDiscoveryUrl);
      if (urlError) {
        sendJson(res, 400, { ok: false, error: urlError });
        return;
      }

      const result = await importDiscoveryMetadata(rawDiscoveryUrl);
      if (!result.ok) {
        sendJson(res, 400, { ok: false, error: result.error });
        return;
      }

      oidcEnvironmentConfig[environmentKey] = {
        discoveryUrl: rawDiscoveryUrl,
        discoveredAt: new Date().toISOString(),
        ...result.metadata
      };
      schedulePersistState();

      sendJson(res, 200, {
        ok: true,
        environment: { key: environmentKey, ...oidcEnvironmentConfig[environmentKey] }
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/saml/service-providers") {
      const session = getOrCreateSession(req, res);
      const flash = consumeFlash(session);
      const model = {
        serviceProviders: attachSamlFlowsToServiceProviders(samlServiceProviderService.listSamlServiceProviders().map(sanitizeSamlServiceProviderForUi)),
        flash
      };
      sendHtml(res, renderSamlServiceProvidersPage(model));
      return;
    }

    if (req.method === "GET" && url.pathname === "/saml/service-providers/new") {
      const session = getOrCreateSession(req, res);
      sendHtml(res, renderSamlServiceProviderNewPage({
        flash: consumeFlash(session),
        ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi)
      }));
      return;
    }

    if (req.method === "POST" && url.pathname === "/saml/service-providers") {
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "saml-sp-create", 20, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return;
      }
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const result = samlServiceProviderService.createSamlServiceProvider(body);

      if (!result.ok) {
        sendHtml(res, renderSamlServiceProviderNewPage({
          flash: consumeFlash(session),
          form: result.validation,
          ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi)
        }));
        return;
      }

      addSessionLog(session, "info", "saml_sp_created", "SAML Service Provider created.", {
        serviceProviderId: result.serviceProvider.id,
        name: result.serviceProvider.name
      });
      setFlash(
        session,
        result.validation.warnings.length ? "warn" : "info",
        result.validation.warnings.length
          ? `SAML Service Provider created. ${result.validation.warnings.join(" ")}`
          : "SAML Service Provider created."
      );
      redirect(res, "/saml/service-providers");
      return;
    }

    const samlEditId = req.method === "GET" ? matchSamlServiceProviderEditPath(url.pathname) : null;
    if (samlEditId) {
      const session = getOrCreateSession(req, res);
      const sp = samlServiceProviderService.getSamlServiceProvider(samlEditId);
      if (!sp) {
        setFlash(session, "warn", "SAML Service Provider not found.");
        redirect(res, "/saml/service-providers");
        return;
      }
      const sanitizedSp = sanitizeSamlServiceProviderForUi(sp);
      sendHtml(res, renderSamlServiceProviderEditPage({
        serviceProvider: sanitizedSp,
        flash: consumeFlash(session),
        ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi),
        acsUrl: sanitizedSp.acsUrl
      }));
      return;
    }

    const samlDeleteId = req.method === "POST" ? matchSamlServiceProviderDeletePath(url.pathname) : null;
    if (samlDeleteId) {
      const session = getOrCreateSession(req, res);
      if (!samlServiceProviderService.deleteSamlServiceProvider(samlDeleteId)) {
        setFlash(session, "warn", "SAML Service Provider not found.");
        redirect(res, "/saml/service-providers");
        return;
      }
      addSessionLog(session, "info", "saml_sp_deleted", "SAML Service Provider deleted.", { serviceProviderId: samlDeleteId });
      setFlash(session, "info", "SAML Service Provider deleted.");
      redirect(res, "/saml/service-providers");
      return;
    }

    const samlUpdateId = req.method === "POST" ? matchSamlServiceProviderUpdatePath(url.pathname) : null;
    if (samlUpdateId && samlUpdateId.startsWith("saml_sp_")) {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const result = samlServiceProviderService.updateSamlServiceProvider(samlUpdateId, body);

      if (result.notFound) {
        setFlash(session, "warn", "SAML Service Provider not found.");
        redirect(res, "/saml/service-providers");
        return;
      }

      if (!result.ok) {
        sendHtml(res, renderSamlServiceProviderEditPage({
          serviceProvider: sanitizeSamlServiceProviderForUi(result.serviceProvider),
          flash: consumeFlash(session),
          form: result.validation,
          ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi),
          acsUrl: `${BASE_URL}/saml/acs/${samlUpdateId}`
        }));
        return;
      }

      addSessionLog(session, "info", "saml_sp_updated", "SAML Service Provider updated.", {
        serviceProviderId: result.serviceProvider.id,
        name: result.serviceProvider.name
      });
      setFlash(
        session,
        result.validation.warnings.length ? "warn" : "info",
        result.validation.warnings.length
          ? `SAML Service Provider updated. ${result.validation.warnings.join(" ")}`
          : "SAML Service Provider updated."
      );
      redirect(res, "/saml/service-providers");
      return;
    }

    const samlFlowStartId = (req.method === "POST" || req.method === "GET") ? matchSamlFlowStartPath(url.pathname) : null;
    if (samlFlowStartId) {
      const session = getOrCreateSession(req, res);

      if (!checkRateLimit(session.id, "saml-flow-start", 10, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return;
      }

      const sp = samlServiceProviderService.getSamlServiceProvider(samlFlowStartId);
      if (!sp) {
        setFlash(session, "warn", "SAML Service Provider not found.");
        redirect(res, "/saml/service-providers");
        return;
      }

      if (sp.requestSigned) {
        setFlash(session, "error", "Signed AuthnRequest is not implemented yet.");
        redirect(res, `/saml/service-providers/${encodeURIComponent(sp.id)}/edit`);
        return;
      }

      // Resolve IdP metadata
      let idpMetadata;
      try {
        let metadataXml = sp.idpMetadataXml;
        if (!metadataXml && sp.idpMetadataUrl) {
          metadataXml = await fetchIdpMetadataFromUrl(sp.idpMetadataUrl);
        }
        if (!metadataXml) {
          throw new Error("No IdP metadata configured. Provide an URL or paste XML in the Service Provider settings.");
        }
        idpMetadata = parseIdpMetadata(metadataXml);
        if (!idpMetadata.ssoUrl) {
          throw new Error("IdP SSO URL not found in metadata. Check the XML or the metadata URL.");
        }
      } catch (error) {
        appLog("warn", "saml_flow_start: metadata error", { spId: sp.id, error: error.message });
        setFlash(session, "error", `IdP metadata error: ${error.message}`);
        redirect(res, `/saml/service-providers/${encodeURIComponent(sp.id)}/edit`);
        return;
      }

      const requestId = generateAuthnRequestId();
      const relayState = generateRelayState();
      const acsUrl = `${BASE_URL}/saml/acs/${sp.id}`;
      const issueInstant = new Date().toISOString();

      const authnRequestXml = buildAuthnRequestXml({
        requestId,
        issueInstant,
        destination: idpMetadata.ssoUrl,
        acsUrl,
        spEntityId: sp.spEntityId,
        nameIdFormat: sp.nameIdFormat || ""
      });

      const env = getEzAccessEnvironment(sp.environment || "");
      const envLabel = env?.key === "preprod" ? "Preprod" : env?.key === "prod" ? "Prod" : "";

      const flow = samlFlowService.createFlow(sp.id, {
        relayState: "received / redacted",
        relayStatePresent: true,
        relayStateSha25612: shortHash(relayState),
        requestId,
        ssoUrl: idpMetadata.ssoUrl,
        idpEntityId: idpMetadata.entityId,
        spEntityId: sp.spEntityId,
        acsUrl,
        nameIdFormat: sp.nameIdFormat || "",
        authorizationUrl: "",
        serviceProviderName: sp.name,
        environment: sp.environment || "",
        environmentLabel: envLabel
      });

      const startHttpMethod = req.method || "POST";

      if (idpMetadata.ssoBinding !== "HTTP-Redirect") {
        const unsupportedBindingRaw = buildUnsupportedSamlBindingRaw(idpMetadata);
        samlFlowService.addFlowStep(flow.id, {
          stepName: "authn_request_created",
          status: "success",
          httpMethod: startHttpMethod,
          endpoint: `/saml/flows/start/${sp.id}`,
          completedAt: new Date().toISOString(),
          requestData: {
            request_id: requestId,
            sp_entity_id: sp.spEntityId,
            acs_url: acsUrl,
            destination: idpMetadata.ssoUrl,
            name_id_format: sp.nameIdFormat || "(unspecified)",
            issue_instant: issueInstant,
            idp_entity_id: idpMetadata.entityId || "(not found in metadata)",
            idp_has_certificate: idpMetadata.hasCertificate ? "yes" : "not found",
            binding_used_for_request: "not implemented"
          },
          responseData: {
            authn_request: "generated",
            encoding: "not performed",
            warning: "HTTP-POST AuthnRequest binding not implemented"
          },
          rawRequestData: buildSamlAuthnRequestRaw({
            authnRequestXml,
            requestId,
            issueInstant,
            idpMetadata,
            sp,
            acsUrl,
            samlRequestParam: "",
            relayState,
            authorizationUrl: ""
          }),
          rawResponseData: buildSamlSyntheticResponseRaw({
            rawType: "Synthetic local response",
            status: 0,
            note: "AuthnRequest generated locally; encoding skipped because HTTP-POST AuthnRequest binding is not implemented."
          })
        });

        samlFlowService.addFlowStep(flow.id, {
          stepName: "redirect_to_idp",
          status: "error",
          httpMethod: "POST",
          endpoint: idpMetadata.ssoUrl,
          httpStatus: null,
          completedAt: new Date().toISOString(),
          requestData: {
            sso_url: idpMetadata.ssoUrl,
            metadata_binding: idpMetadata.ssoBinding || "not found",
            binding_used: "not implemented"
          },
          responseData: {
            redirect_to: "not performed",
            warning: "HTTP-POST AuthnRequest binding not implemented"
          },
          rawRequestData: unsupportedBindingRaw,
          rawResponseData: {
            ...unsupportedBindingRaw,
            raw_type: "Synthetic local response",
            local_http_status: "not emitted"
          },
          errorData: {
            error: "HTTP-POST AuthnRequest binding not implemented"
          }
        });

        samlFlowService.completeFlow(flow.id, {
          status: "failed",
          failedStep: "redirect_to_idp",
          errorCode: "saml_authn_request_post_binding_not_implemented",
          errorDescription: "HTTP-POST AuthnRequest binding not implemented."
        });

        redirect(res, `/saml/flows/${encodeURIComponent(flow.id)}`);
        return;
      }

      let samlRequestParam;
      try {
        samlRequestParam = encodeAuthnRequestForRedirect(authnRequestXml);
      } catch (error) {
        appLog("warn", "saml_flow_start: encode error", { spId: sp.id, error: error.message });
        setFlash(session, "error", "Failed to encode AuthnRequest.");
        redirect(res, `/saml/service-providers/${encodeURIComponent(sp.id)}/edit`);
        return;
      }

      const authorizationUrl = buildSsoRedirectUrl(idpMetadata.ssoUrl, samlRequestParam, relayState);
      samlFlowService.updateFlow(flow.id, {
        runtime: {
          ...flow.runtime,
          authorizationUrl: redactSamlRedirectUrl(authorizationUrl),
          authorizationUrlNature: "redacted browser redirect URL"
        }
      });

      samlFlowService.addFlowStep(flow.id, {
        stepName: "authn_request_created",
        status: "success",
        httpMethod: startHttpMethod,
        endpoint: `/saml/flows/start/${sp.id}`,
        completedAt: new Date().toISOString(),
        requestData: {
          request_id: requestId,
          sp_entity_id: sp.spEntityId,
          acs_url: acsUrl,
          destination: idpMetadata.ssoUrl,
          name_id_format: sp.nameIdFormat || "(unspecified)",
          issue_instant: issueInstant,
          idp_entity_id: idpMetadata.entityId || "(not found in metadata)",
          idp_has_certificate: idpMetadata.hasCertificate ? "yes" : "not found",
          expected_response_protocol_binding: "HTTP-POST",
          binding_used_for_request: "HTTP-Redirect",
          saml_request_encoded_size_bytes: Buffer.byteLength(samlRequestParam, "utf8"),
          saml_request_sha256_12: shortHash(samlRequestParam),
          relay_state: "present",
          relay_state_sha256_12: shortHash(relayState)
        },
        responseData: {
          authn_request: "generated",
          encoding: "HTTP-Redirect (deflate + base64)",
          raw_nature: "Prepared SAML AuthnRequest"
        },
        rawRequestData: buildSamlAuthnRequestRaw({
          authnRequestXml,
          requestId,
          issueInstant,
          idpMetadata,
          sp,
          acsUrl,
          samlRequestParam,
          relayState,
          authorizationUrl
        }),
        rawResponseData: buildSamlSyntheticResponseRaw({
          rawType: "Synthetic local response",
          status: 0,
          note: "AuthnRequest generated and encoded locally before redirect."
        })
      });

      samlFlowService.addFlowStep(flow.id, {
        stepName: "redirect_to_idp",
        status: "success",
        httpMethod: "GET",
        endpoint: idpMetadata.ssoUrl,
        httpStatus: 302,
        completedAt: new Date().toISOString(),
        requestData: {
          sso_url: idpMetadata.ssoUrl,
          relay_state: "present",
          relay_state_sha256_12: shortHash(relayState),
          saml_request: "present",
          saml_request_encoded_size_bytes: Buffer.byteLength(samlRequestParam, "utf8"),
          saml_request_sha256_12: shortHash(samlRequestParam),
          binding: "HTTP-Redirect",
          http_mode: "browser redirect"
        },
        responseData: {
          redirect_to: "IdP SSO endpoint",
          redirect_url: "redacted raw available",
          local_http_status: "302 synthetic/local",
          awaiting: "SAMLResponse on ACS",
          raw_nature: "Prepared browser redirect"
        },
        rawRequestData: buildSamlRedirectRaw({ authorizationUrl, idpMetadata, samlRequestParam, relayState }),
        rawResponseData: buildSamlSyntheticResponseRaw({
          rawType: "Synthetic local response",
          status: 302,
          note: "Local 302 sent by this app to the browser; this is not an IdP response."
        })
      });

      addSessionLog(session, "info", "saml_flow_started", "SAML flow started.", {
        flowId: flow.id,
        serviceProviderId: sp.id
      });

      redirect(res, authorizationUrl);
      return;
    }

    const samlAcsId = req.method === "POST" ? matchSamlAcsPath(url.pathname) : null;
    if (samlAcsId) {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);

      const samlResponseParam = body.SAMLResponse || "";
      const relayState = body.RelayState || "";

      const runningFlow = samlFlowService.findRunningFlowByRelayState(relayState, SAML_FLOW_TTL_MS);
      if (!runningFlow) {
        appLog("warn", "SAML ACS: no matching running flow", { hasRelayState: Boolean(relayState) });
        sendJson(res, 400, { error: "No running SAML flow matches this RelayState. The flow may have expired or the RelayState is invalid." });
        return;
      }

      samlFlowService.addFlowStep(runningFlow.id, {
        stepName: "acs_callback_received",
        status: "success",
        httpMethod: "POST",
        endpoint: url.pathname,
        completedAt: new Date().toISOString(),
        requestData: {
          relay_state: relayState ? "present" : "missing",
          relay_state_sha256_12: relayState ? shortHash(relayState) : "",
          saml_response: samlResponseParam ? "present" : "missing",
          saml_response_size_bytes: samlResponseParam ? Buffer.byteLength(samlResponseParam, "utf8") : 0,
          saml_response_sha256_12: samlResponseParam ? shortHash(samlResponseParam) : ""
        },
        responseData: {
          raw_nature: "Reconstructed inbound ACS request"
        },
        rawRequestData: buildSamlAcsRequestRaw({ req, url, body, samlResponseParam, relayState }),
        rawResponseData: buildSamlSyntheticResponseRaw({
          rawType: "Synthetic local response",
          status: 302,
          note: "ACS handled locally and redirected to the flow result page."
        })
      });

      if (!samlResponseParam) {
        samlFlowService.addFlowStep(runningFlow.id, {
          stepName: "saml_response_received",
          status: "error",
          httpMethod: "POST",
          endpoint: url.pathname,
          completedAt: new Date().toISOString(),
          responseData: {
            decoded: "skipped",
            raw_nature: "Skipped"
          },
          rawRequestData: buildSamlAcsRequestRaw({ req, url, body, samlResponseParam, relayState }),
          rawResponseData: buildSamlSyntheticResponseRaw({
            rawType: "Synthetic local response",
            status: 302,
            note: "ACS rejected missing SAMLResponse and redirected to the flow result page."
          }),
          errorData: { error: "SAMLResponse parameter is missing from the ACS POST body." }
        });
        samlFlowService.completeFlow(runningFlow.id, {
          status: "failed",
          failedStep: "saml_response_received",
          errorCode: "saml_response_missing",
          errorDescription: "No SAMLResponse in ACS callback."
        });
        redirect(res, `/saml/flows/${encodeURIComponent(runningFlow.id)}`);
        return;
      }

      let responseXml;
      try {
        responseXml = decodeSamlResponse(samlResponseParam);
      } catch {
        samlFlowService.addFlowStep(runningFlow.id, {
          stepName: "saml_response_received",
          status: "error",
          httpMethod: "POST",
          endpoint: url.pathname,
          completedAt: new Date().toISOString(),
          responseData: {
            decoded: "error",
            raw_nature: "Decoded SAMLResponse redacted"
          },
          rawRequestData: buildEncodedSamlResponseRaw({ samlResponseParam, relayState, path: url.pathname }),
          rawResponseData: buildSamlDecodeErrorRaw({ samlResponseParam, relayState, path: url.pathname }),
          errorData: { error: "Failed to base64-decode SAMLResponse." }
        });
        samlFlowService.completeFlow(runningFlow.id, {
          status: "failed",
          failedStep: "saml_response_received",
          errorCode: "saml_response_decode_error",
          errorDescription: "SAMLResponse is not valid base64."
        });
        redirect(res, `/saml/flows/${encodeURIComponent(runningFlow.id)}`);
        return;
      }

      samlFlowService.addFlowStep(runningFlow.id, {
        stepName: "saml_response_received",
        status: "success",
        httpMethod: "POST",
        endpoint: url.pathname,
        completedAt: new Date().toISOString(),
        requestData: {
          saml_response: "received",
          relay_state: relayState ? "present" : "missing",
          relay_state_sha256_12: relayState ? shortHash(relayState) : "",
          encoded_size_bytes: Buffer.byteLength(samlResponseParam, "utf8"),
          encoded_sha256_12: shortHash(samlResponseParam),
          decoded_xml_size_bytes: Buffer.byteLength(responseXml, "utf8"),
          decoded_xml_sha256_12: shortHash(responseXml)
        },
        responseData: {
          decoded: "success",
          raw_nature: "Decoded SAMLResponse redacted"
        },
        rawRequestData: buildEncodedSamlResponseRaw({ samlResponseParam, relayState, path: url.pathname }),
        rawResponseData: buildDecodedSamlResponseRaw({ responseXml, samlResponseParam, relayState, path: url.pathname })
      });

      let parsed;
      try {
        parsed = parseSamlResponse(responseXml);
      } catch {
        samlFlowService.addFlowStep(runningFlow.id, {
          stepName: "saml_response_decoded",
          status: "error",
          httpMethod: "POST",
          endpoint: url.pathname,
          completedAt: new Date().toISOString(),
          responseData: {
            parsed: "error",
            signature_verification_result: "not_checked",
            trust_validation: "incomplete"
          },
          rawRequestData: buildDecodedSamlResponseRaw({ responseXml, samlResponseParam, relayState, path: url.pathname }),
          rawResponseData: buildSamlSyntheticResponseRaw({
            rawType: "Parsed SAMLResponse summary redacted",
            status: 0,
            note: "Parsing failed; no parsed summary available."
          }),
          errorData: { error: "Failed to parse SAMLResponse XML." }
        });
        samlFlowService.completeFlow(runningFlow.id, {
          status: "failed",
          failedStep: "saml_response_decoded",
          errorCode: "saml_response_parse_error",
          errorDescription: "SAMLResponse XML could not be parsed."
        });
        redirect(res, `/saml/flows/${encodeURIComponent(runningFlow.id)}`);
        return;
      }

      // Trust validation — cryptographic + semantic, fail-closed
      const acsSpRecord = samlServiceProviderService.getSamlServiceProvider(samlAcsId);
      let idpMetadataXmlForVerif = acsSpRecord?.idpMetadataXml || "";
      if (!idpMetadataXmlForVerif && acsSpRecord?.idpMetadataUrl) {
        try {
          idpMetadataXmlForVerif = await fetchIdpMetadataFromUrl(acsSpRecord.idpMetadataUrl);
        } catch {
          // Metadata fetch failed — signature verification will be incomplete
          appLog("warn", "saml_acs: metadata fetch failed for verification", { spId: samlAcsId });
        }
      }
      const idpSigningCerts = idpMetadataXmlForVerif ? extractIdpSigningCertificates(idpMetadataXmlForVerif) : [];
      const idpCertFingerprints = idpSigningCerts.map((c) => shortHash(c));
      const idpMetadataParsed = idpMetadataXmlForVerif ? parseIdpMetadata(idpMetadataXmlForVerif) : null;
      const idpEntityId = idpMetadataParsed?.entityId || "";

      let sigVerification;
      try {
        sigVerification = verifySamlXmlSignatures(responseXml, idpSigningCerts);
      } catch {
        sigVerification = {
          response_signature_present: parsed.responseSignaturePresent ? "present" : "missing",
          assertion_signature_present: parsed.assertionSignaturePresent ? "present" : "missing",
          response_signature_verification: "unavailable",
          assertion_signature_verification: "unavailable",
          signature_verification_result: "unavailable",
          trust_validation: "incomplete",
          verification_note: "Unexpected error during signature verification."
        };
      }

      const xswProtection = checkXswProtection(responseXml, parsed);
      const issuerValidation = evaluateSamlIssuerValidation(parsed, idpEntityId);
      const audienceValidation = evaluateSamlAudienceValidation(parsed, runningFlow.runtime?.spEntityId);
      const destinationValidation = evaluateSamlDestinationValidation(parsed, runningFlow.runtime?.acsUrl);
      const inResponseToValidation = evaluateSamlInResponseTo(parsed, runningFlow.runtime?.requestId);
      const subjectConfirmationValidation = evaluateSamlSubjectConfirmation(
        parsed,
        runningFlow.runtime?.acsUrl,
        runningFlow.runtime?.requestId
      );
      const temporalValidation = evaluateSamlTemporalConditions(parsed);
      const replayValidation = checkSamlReplay(parsed);
      const metadataCertificates = {
        available: idpSigningCerts.length > 0,
        count: idpSigningCerts.length,
        sha256_12: idpCertFingerprints,
        source: "idp_metadata"
      };

      const trustResult = evaluateSamlTrustValidation({
        signatureVerification: sigVerification,
        xswProtection,
        issuerValidation,
        audienceValidation,
        destinationValidation,
        inResponseToValidation,
        subjectConfirmationValidation,
        temporalValidation,
        replayValidation,
        metadataCertificates
      });

      const attrCount = Object.keys(parsed.attributes || {}).length;

      // Consistency checks — used in UI "Consistency checks" panel
      const diagnostics = {
        in_response_to_vs_request_id: inResponseToValidation.result,
        destination_vs_acs_url: destinationValidation.result,
        audience_vs_sp_entity_id: audienceValidation.result,
        temporal_conditions: temporalValidation.result,
        xsw_protection: xswProtection.result,
        issuer_validation: issuerValidation.result
      };

      const statusMessage = sanitizeSamlDiagnosticValue(parsed.statusMessage || "(not extracted)", "status_message");
      samlFlowService.addFlowStep(runningFlow.id, {
        stepName: "saml_response_decoded",
        status: parsed.isSuccess ? "success" : "error",
        httpMethod: "POST",
        endpoint: url.pathname,
        completedAt: new Date().toISOString(),
        requestData: {
          response_issuer: parsed.issuer || "(not found)",
          in_response_to: parsed.inResponseTo || "(not found)",
          destination: parsed.destination || "(not found)",
          status_code: parsed.statusCode || "(not found)",
          status_message: statusMessage,
          status_detail: parsed.statusDetailPresent ? "present" : "missing"
        },
        responseData: {
          assertion_present: parsed.assertionPresent ? "yes" : "no",
          assertion_issuer: parsed.assertionIssuer || "(not extracted)",
          subject_present: parsed.subjectPresent ? "yes" : "no",
          name_id_present: parsed.nameIdPresent ? "yes" : "no",
          name_id_preview: parsed.nameIdPreview || "(not present)",
          name_id_hash: parsed.nameIdHash || "",
          name_id_format: parsed.nameIdFormat || "(not present)",
          saml_status: parsed.isSuccess ? "Success" : "Failure",
          attributes_count: attrCount,
          attribute_names: parsed.attributeNames || [],
          ...(attrCount > 0 ? { attributes_redacted: parsed.attributes } : {}),
          session_index: parsed.sessionIndexPresent
            ? { present: true, sha256_12: parsed.sessionIndexHash }
            : { present: false },
          conditions_present: parsed.conditionsPresent ? "yes" : "no",
          conditions_evaluated: temporalValidation.conditions_evaluated ? "yes" : "no",
          temporal_conditions_status: temporalValidation.result,
          audience_restriction_present: parsed.audienceRestrictionPresent ? "yes" : "no",
          audience: parsed.audience || "(not extracted)",
          subject_confirmation_present: parsed.subjectConfirmationPresent ? "yes" : "no",
          recipient: parsed.recipient || "(not extracted)",
          not_before: parsed.notBefore || "(not extracted)",
          not_on_or_after: parsed.notOnOrAfter || "(not extracted)",
          response_signature_present: sigVerification.response_signature_present,
          assertion_signature_present: sigVerification.assertion_signature_present,
          response_signature_verification: sigVerification.response_signature_verification,
          assertion_signature_verification: sigVerification.assertion_signature_verification,
          signature_verification_result: sigVerification.signature_verification_result,
          trust_validation: trustResult.trust_validation,
          trust_validation_checks: trustResult.checks,
          trust_validation_errors: trustResult.errors,
          trust_validation_warnings: trustResult.warnings,
          idp_certificates_used: idpCertFingerprints.length,
          verification_note: sigVerification.verification_note || "",
          issuer_validation: issuerValidation.result,
          temporal_validation: temporalValidation.result,
          replay_validation: replayValidation.result,
          xsw_protection: xswProtection.result,
          diagnostic_comparisons: diagnostics
        },
        rawRequestData: buildDecodedSamlResponseRaw({ responseXml, samlResponseParam, relayState, path: url.pathname }),
        rawResponseData: buildParsedSamlSummaryRaw({
          parsed, diagnostics, attrCount, sigVerification, idpCertFingerprints,
          trustResult, xswProtection, issuerValidation, audienceValidation,
          destinationValidation, inResponseToValidation, subjectConfirmationValidation,
          temporalValidation, replayValidation, metadataCertificates
        }),
        errorData: parsed.isSuccess ? null : { saml_status: parsed.statusCode }
      });

      samlFlowService.completeFlow(runningFlow.id, {
        status: parsed.isSuccess ? "success" : "failed",
        failedStep: parsed.isSuccess ? "" : "saml_response_decoded",
        errorCode: parsed.isSuccess ? "" : "saml_status_not_success",
        errorDescription: parsed.isSuccess ? "" : `IdP returned status: ${parsed.statusCode}`
      });

      addSessionLog(session, parsed.isSuccess ? "info" : "warn", "saml_acs_callback", "SAML ACS callback processed.", {
        flowId: runningFlow.id,
        success: parsed.isSuccess
      });

      redirect(res, `/saml/flows/${encodeURIComponent(runningFlow.id)}`);
      return;
    }

    const samlFlowResultId = req.method === "GET" ? matchSamlFlowResultPath(url.pathname) : null;
    if (samlFlowResultId) {
      const session = getOrCreateSession(req, res);
      const model = buildSamlFlowViewModel(session, samlFlowResultId, url);
      if (!model) {
        setFlash(session, "warn", "SAML flow not found.");
        redirect(res, "/saml/service-providers");
        return;
      }
      sendHtml(res, renderSamlFlowResultPage(model));
      return;
    }

    const samlFlowDetailsId = req.method === "GET" ? matchSamlFlowDetailsPath(url.pathname) : null;
    if (samlFlowDetailsId) {
      const session = getOrCreateSession(req, res);
      const model = buildSamlFlowViewModel(session, samlFlowDetailsId, url);
      if (!model) {
        setFlash(session, "warn", "SAML flow not found.");
        redirect(res, "/saml/service-providers");
        return;
      }
      sendHtml(res, renderSamlFlowDetailsPage(model));
      return;
    }

    if ((req.method === "GET" || req.method === "POST") && url.pathname === "/oidc/callback") {
      const session = getOrCreateSession(req, res);
      const rawBody = req.method === "POST" ? await readBody(req) : "";
      const body = req.method === "POST" ? parseBody(req, rawBody) : {};
      const params = req.method === "POST" ? body : Object.fromEntries(url.searchParams.entries());

      const newUiFlow = findRunningFlowByCallbackState(params.state || "");
      if (newUiFlow) {
        const completedFlow = await processNewUiCallback({ req, flow: newUiFlow, params });
        redirect(res, `/oidc/flows/${encodeURIComponent(completedFlow.id)}`);
        return;
      }

      const invalidStateFlow = findSingleRecentRunningOidcFlow();
      if (invalidStateFlow) {
        const completedFlow = await processNewUiCallback({ req, flow: invalidStateFlow, params });
        redirect(res, `/oidc/flows/${encodeURIComponent(completedFlow.id)}`);
        return;
      }

      sendJson(res, 404, {
        error: "No running flow matches this OIDC callback state."
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      const currentProviderConfig = sanitizeProviderConfig(providerConfig);
      sendJson(res, 200, {
        status: "ok",
        nodeEnv: NODE_ENV,
        redirectUri: currentProviderConfig.redirectUri,
        oidc: { serviceProviders: serviceProviders.length, flows: flows.length },
        saml: { serviceProviders: samlServiceProviders.length, flows: samlFlows.length }
      });
      return;
    }

    if (ensureHtmlSessionRoute(req)) {
      sendHtmlStatus(
        res,
        404,
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>Route not found</title></head><body><h1>404</h1><p>Route not found.</p><p><a href=\"/\">Back to dashboard</a></p></body></html>"
      );
      return;
    }

    sendJson(res, 404, {
      error: "Route not found."
    });
  } catch (error) {
    if (error.code === "BODY_TOO_LARGE") {
      sendJson(res, 413, { error: "Request body too large." });
      return;
    }
    appLog("error", "Unhandled error", {
      error: error.message,
      path: url.pathname
    });
    sendJson(res, 500, {
      error: "Internal error."
    });
  }
});

async function shutdown(signal) {
  appLog("info", "Server stopping, persisting state", { signal });
  try {
    await flushPersistState();
  } finally {
    process.exit(0);
  }
}

process.on("SIGINT", () => {
  shutdown("SIGINT");
});

process.on("SIGTERM", () => {
  shutdown("SIGTERM");
});

async function start() {
  await ensureRuntimeSecrets();
  await loadPersistedState();

  if (IS_RENDER && !process.env.BASE_URL && RENDER_EXTERNAL_URL) {
    appLog("warn", "BASE_URL missing: using RENDER_EXTERNAL_URL as the public URL.", {
      renderExternalUrl: RENDER_EXTERNAL_URL,
      redirectUri: createProviderConfig().redirectUri
    });
  }

  if (IS_RENDER && !process.env.STORAGE_DIR) {
    appLog("warn", "STORAGE_DIR missing on Render: using /app/storage. Make sure a persistent disk is mounted at this path.", {
      storageDir: STORAGE_DIR,
      stateFile: STATE_FILE
    });
  }

  server.listen(PORT, () => {
    appLog("info", "Serveur demarre", {
      port: PORT,
      baseUrl: BASE_URL,
      nodeEnv: NODE_ENV,
      logLevel: LOG_LEVEL,
      storageDir: STORAGE_DIR,
      stateFile: STATE_FILE,
      sessionSecretSource: runtimeSecretSource,
      sessionSecretFile: process.env.SESSION_SECRET ? null : SESSION_SECRET_FILE,
      redirectUri: sanitizeProviderConfig(providerConfig).redirectUri,
      oidcServiceProviders: serviceProviders.length,
      oidcFlows: flows.length,
      samlServiceProviders: samlServiceProviders.length
    });
  });
}

start().catch((error) => {
  appLog("error", "Impossible de demarrer le serveur", {
    error: error.message
  });
  process.exit(1);
});
