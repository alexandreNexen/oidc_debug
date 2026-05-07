import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getEzAccessEnvironment, listEzAccessEnvironments } from "./protocols/oidc/config.js";
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
import { renderDashboard } from "./protocols/oidc/views/dashboard.js";
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
  parseSamlResponse
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

  if (contentType.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(body).entries());
  }

  if (contentType.includes("application/json")) {
    return safeJsonParse(body);
  }

  return body;
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
    url: request.url || "",
    headers,
    params: request.params || {},
    body: parsedBody || undefined
  });
}

function sanitizeRawResponse(response = null) {
  if (!response) {
    return null;
  }

  const contentType = response.headers?.["content-type"] || response.headers?.["Content-Type"] || "";
  const parsedBody = response.parsed || parseSnapshotBody(response.body || "", contentType);

  return sanitizeDiagnosticData({
    status: response.status ?? 0,
    ok: Boolean(response.ok),
    headers: response.headers || {},
    body: parsedBody || response.redactedBody || response.error || "",
    error: response.error || "",
    diagnostics: response.diagnostics || null
  });
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

function buildPersistedState() {
  return {
    version: 4,
    updatedAt: new Date().toISOString(),
    oidc: {
      providerConfig: sanitizeProviderConfig(providerConfig),
      serviceProviders,
      flows,
      flowSteps
    },
    saml: {
      serviceProviders: samlServiceProviders,
      flows: samlFlows,
      flowSteps: samlFlowSteps
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
    serviceProviderService.hydrateServiceProviders(hydrated.oidc?.serviceProviders || []);
    flowService.hydrateFlows(hydrated.oidc?.flows || [], hydrated.oidc?.flowSteps || []);
    samlServiceProviderService.hydrateSamlServiceProviders(hydrated.saml?.serviceProviders || []);
    samlFlowService.hydrateSamlFlows(hydrated.saml?.flows || [], hydrated.saml?.flowSteps || []);

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
          expectedState: candidate.flow?.expectedState || "",
          expectedNonce: candidate.flow?.expectedNonce || "",
          codeVerifier: candidate.flow?.codeVerifier || "",
          codeChallenge: candidate.flow?.codeChallenge || ""
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

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  ...(IS_HTTPS_MODE ? { "strict-transport-security": "max-age=63072000; includeSubDomains" } : {})
};

const rateLimitMap = new Map();

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
  const match = pathname.match(/^\/service-providers\/([^/]+)\/edit$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchServiceProviderUpdatePath(pathname) {
  const match = pathname.match(/^\/service-providers\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchServiceProviderDeletePath(pathname) {
  const match = pathname.match(/^\/service-providers\/([^/]+)\/delete$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowStartPath(pathname) {
  const match = pathname.match(/^\/flows\/start\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowResultPath(pathname) {
  const match = pathname.match(/^\/flows\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowDetailsPath(pathname) {
  const match = pathname.match(/^\/flows\/([^/]+)\/details$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchFlowRerunPath(pathname) {
  const match = pathname.match(/^\/flows\/([^/]+)\/rerun$/);
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
  const allowed = ["iss", "sub", "aud", "exp", "iat", "email", "name", "groups", "roles"];
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

function samlFlowSummary(flow) {
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

function samlStepSummary(stepName, step) {
  return {
    stepName,
    status: step?.status || "pending",
    badge: stepStatusLabel(step?.status || "pending"),
    httpMethod: step?.httpMethod || "",
    endpoint: step?.endpoint || "",
    httpStatus: step?.httpStatus ?? null,
    requestData: step?.requestData || null,
    responseData: step?.responseData || null,
    rawRequestData: step?.rawRequestData || null,
    rawResponseData: step?.rawResponseData || null,
    errorData: step?.errorData || null,
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
    flow: samlFlowSummary(flow),
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
    serviceProviderId: flow.serviceProviderId,
    status: flow.status,
    statusBadge: flowStatusLabel(flow.status),
    startedAt: flow.startedAt,
    completedAt: flow.completedAt,
    failedStep: flow.failedStep,
    errorCode: flow.errorCode,
    errorDescription: flow.errorDescription,
    durationMs: flow.durationMs,
    serviceProviderName: flow.runtime?.serviceProviderName || "",
    clientId: flow.runtime?.clientId || "",
    environment: flow.runtime?.environment || "",
    environmentLabel: flow.runtime?.environmentLabel || environmentLabel(flow.runtime?.environment)
  };
}

function flowStepSummary(stepName, step) {
  return {
    stepName,
    status: step?.status || "pending",
    badge: stepStatusLabel(step?.status || "pending"),
    httpMethod: step?.httpMethod || "",
    endpoint: step?.endpoint || "",
    httpStatus: step?.httpStatus ?? null,
    requestData: step?.requestData || null,
    responseData: step?.responseData || null,
    rawRequestData: step?.rawRequestData || null,
    rawResponseData: step?.rawResponseData || null,
    errorData: step?.errorData || null,
    createdAt: step?.createdAt || null,
    completedAt: step?.completedAt || null
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
  return entries.map((serviceProvider) => ({
    ...serviceProvider,
    lastFlow: flowSummary(flowService.getLastFlowForServiceProvider(serviceProvider.id))
  }));
}

function buildAuthorizeStep({ flow, runConfig, prepared }) {
  return {
    stepName: "authorize",
    status: "success",
    httpMethod: "GET",
    endpoint: runConfig.config.authorizationEndpoint,
    httpStatus: 302,
    requestData: {
      method: "GET",
      endpoint: runConfig.config.authorizationEndpoint,
      environment: flow.runtime?.environmentLabel || "",
      client_id: runConfig.config.clientId,
      redirect_uri: runConfig.config.redirectUri,
      scopes: runConfig.config.scopes,
      response_type: runConfig.config.responseType,
      state: "present",
      nonce: prepared.runtime.nonce ? "present" : "missing",
      pkce: prepared.runtime.codeChallenge ? prepared.config.codeChallengeMethod || "S256" : "disabled"
    },
    responseData: {
      redirect_to: "Ez-Access",
      authorization_url: "present",
      authorization_url_full: prepared.request.url,
      flow_id: flow.id
    },
    rawRequestData: sanitizeRawRequest(prepared.request),
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
    completedAt: new Date().toISOString()
  };
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
    httpStatus: 200,
    requestData: {
      redirect_uri: flow.runtime?.redirectUri || "",
      expected_parameters: "code, state",
      expected_state: "present"
    },
    responseData: {
      code: params.code ? "present" : "missing",
      state: stateCheck === "match" ? "valid" : stateCheck,
      error: params.error || "",
      error_description: params.error_description || ""
    },
    rawRequestData: sanitizeDiagnosticData({
      method: req.method,
      url: "/oidc/callback",
      params
    }),
    rawResponseData: sanitizeDiagnosticData({
      status: 200,
      state: stateCheck === "match" ? "valid" : stateCheck,
      code: params.code ? "present" : "missing",
      error: params.error || "",
      error_description: params.error_description || ""
    }),
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

function buildTokenStep({ requestSnapshot, responseSnapshot }) {
  const parsed = responseSnapshot.parsed || {};
  const idTokenClaims = decodeJwt(parsed.id_token || "");
  const accessTokenClaims = decodeJwt(parsed.access_token || "");
  const ok = Boolean(responseSnapshot.ok && (parsed.access_token || parsed.id_token));

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
      client_id: requestSnapshot.params?.client_id || "sent via Authorization header",
      client_secret: "********",
      redirect_uri: requestSnapshot.params?.redirect_uri || "",
      code: requestSnapshot.params?.code ? "present" : "missing",
      code_verifier: requestSnapshot.params?.code_verifier ? "present" : "missing"
    },
    responseData: {
      http_status: responseSnapshot.status || 0,
      id_token: tokenReceived(parsed.id_token),
      access_token: tokenReceived(parsed.access_token),
      refresh_token: tokenReceived(parsed.refresh_token),
      expires_in: parsed.expires_in || "",
      token_type: parsed.token_type || "",
      error: parsed.error || responseSnapshot.error || "",
      error_description: parsed.error_description || "",
      id_token_claims: idTokenClaims.isJwt ? selectedClaims(idTokenClaims.payload) : {},
      access_token_claims: accessTokenClaims.isJwt ? selectedClaims(accessTokenClaims.payload) : {}
    },
    rawRequestData: sanitizeRawRequest(requestSnapshot),
    rawResponseData: sanitizeRawResponse(responseSnapshot),
    errorData: ok
      ? null
      : {
          errorCode: parsed.error || responseSnapshot.error || "token_exchange_failed",
          errorDescription: parsed.error_description || responseSnapshot.error || "Token endpoint did not return usable tokens.",
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
        Authorization: "Bearer ********"
      },
      responseData: {
        skipped_reason: skippedReason
      },
      rawRequestData: sanitizeRawRequest(requestSnapshot),
      rawResponseData: null,
      errorData: null,
      completedAt: new Date().toISOString()
    };
  }

  const parsed = responseSnapshot.parsed || {};

  return {
    stepName: "userinfo",
    status: responseSnapshot.ok ? "success" : "error",
    httpMethod: "GET",
    endpoint: requestSnapshot.url,
    httpStatus: responseSnapshot.status || 0,
    requestData: {
      method: "GET",
      endpoint: requestSnapshot.url,
      Authorization: "Bearer ********"
    },
    responseData: {
      http_status: responseSnapshot.status || 0,
      ...selectedClaims(parsed),
      error: parsed.error || responseSnapshot.error || "",
      error_description: parsed.error_description || ""
    },
    rawRequestData: sanitizeRawRequest(requestSnapshot),
    rawResponseData: sanitizeRawResponse(responseSnapshot),
    errorData: responseSnapshot.ok
      ? null
      : {
          errorCode: parsed.error || responseSnapshot.error || "userinfo_failed",
          errorDescription: parsed.error_description || responseSnapshot.error || "UserInfo endpoint did not return a successful response.",
          diagnostics: responseSnapshot.diagnostics || null
        },
    completedAt: new Date().toISOString()
  };
}

function failFlow(flowId, failedStep, errorCode, errorDescription) {
  return flowService.completeFlow(flowId, {
    status: "failed",
    failedStep,
    errorCode: errorCode || `${failedStep}_failed`,
    errorDescription: errorDescription || recommendedAction(failedStep)
  });
}

function completePartialFlow(flowId, failedStep, errorCode, errorDescription) {
  return flowService.completeFlow(flowId, {
    status: "partial_success",
    failedStep,
    errorCode: errorCode || "",
    errorDescription: errorDescription || ""
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
        redirectUri: runConfig.provider.redirectUri
      },
      authorizationEndpoint: runConfig.config.authorizationEndpoint,
      tokenEndpoint: runConfig.config.tokenEndpoint,
      userInfoEndpoint: runConfig.config.userInfoEndpoint,
      redirectUri: runConfig.config.redirectUri,
      tokenEndpointAuthMethod: prepared.config.tokenEndpointAuthMethod,
      expectedState: prepared.runtime.state,
      expectedNonce: prepared.runtime.nonce,
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
  const stateCheck = evaluateState(flow.runtime?.expectedState || "", params.state);
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
    const requestSnapshot = buildTokenExchangeRequest({
      config: effectiveConfig,
      code: params.code,
      codeVerifier: flow.runtime?.codeVerifier || ""
    });
    const responseSnapshot = await executeHttp(requestSnapshot);
    const tokenStep = buildTokenStep({ requestSnapshot, responseSnapshot });
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
      completePartialFlow(flow.id, "userinfo", "userinfo_skipped", skippedReason);
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
      completePartialFlow(flow.id, "userinfo", errorData.errorCode, errorData.errorDescription);
      return flowService.getFlow(flow.id);
    }

    flowService.completeFlow(flow.id, { status: "success" });
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
        endpoint: flow.runtime?.tokenEndpoint || "",
        client_id: selected.clientId,
        code: params.code ? "present" : "missing",
        code_verifier: flow.runtime?.codeVerifier ? "present" : "missing"
      }),
      rawResponseData: {
        error: error.message
      },
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

  return {
    session,
    activeTab,
    flash: consumeFlash(session),
    providerConfig: sanitizedProviderConfig,
    serviceProviders: attachFlowsToServiceProviders(serviceProviderService.listServiceProviders().map(sanitizeServiceProviderForUi)),
    recentFlows: flowService.listRecentFlows(5).map(flowSummary),
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

    if (req.method === "GET" && url.pathname === "/service-providers") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "service-providers", url);
      sendHtml(res, renderServiceProvidersPage(model));
      return;
    }

    if (req.method === "GET" && url.pathname === "/service-providers/new") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "service-providers", url);
      sendHtml(res, renderServiceProviderNewPage(model));
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers") {
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
      redirect(res, "/service-providers");
      return;
    }

    const editServiceProviderId = req.method === "GET" ? matchServiceProviderEditPath(url.pathname) : null;
    if (editServiceProviderId) {
      const session = getOrCreateSession(req, res);
      const serviceProvider = getServiceProvider(editServiceProviderId);

      if (!serviceProvider) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/service-providers");
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
        redirect(res, "/service-providers");
        return;
      }

      addSessionLog(session, "info", "service_provider_deleted", "Service Provider deleted.", {
        serviceProviderId: deleteServiceProviderId
      });
      setFlash(session, "info", "Service Provider deleted.");
      redirect(res, "/service-providers");
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
        redirect(res, "/service-providers");
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
      redirect(res, "/service-providers");
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
        redirect(res, "/service-providers");
        return;
      }

      if (!result.ok) {
        redirect(res, `/flows/${encodeURIComponent(result.flow.id)}`);
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
        redirect(res, "/service-providers");
        return;
      }

      const result = await startNewUiFlow(session, flow.serviceProviderId);
      if (!result.ok) {
        redirect(res, result.flow ? `/flows/${encodeURIComponent(result.flow.id)}` : "/service-providers");
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
        redirect(res, "/service-providers");
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
        redirect(res, "/service-providers");
        return;
      }

      sendHtml(res, renderFlowResultPage(model));
      return;
    }

    if (req.method === "GET" && url.pathname === "/saml/service-providers") {
      const session = getOrCreateSession(req, res);
      const flash = consumeFlash(session);
      const model = {
        serviceProviders: samlServiceProviderService.listSamlServiceProviders().map(sanitizeSamlServiceProviderForUi),
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
      const env = getEzAccessEnvironment(sp.environment || "");
      const envLabel = env?.key === "preprod" ? "Preprod" : env?.key === "prod" ? "Prod" : "";

      const flow = samlFlowService.createFlow(sp.id, {
        relayState,
        requestId,
        ssoUrl: idpMetadata.ssoUrl,
        idpEntityId: idpMetadata.entityId,
        spEntityId: sp.spEntityId,
        acsUrl,
        nameIdFormat: sp.nameIdFormat || "",
        authorizationUrl,
        serviceProviderName: sp.name,
        environment: sp.environment || "",
        environmentLabel: envLabel
      });

      const startHttpMethod = req.method || "POST";

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
          idp_has_certificate: idpMetadata.hasCertificate ? "yes" : "not found"
        },
        responseData: {
          authn_request: "generated",
          encoding: "HTTP-Redirect (deflate + base64)"
        },
        rawRequestData: { xml: "[AuthnRequest XML — redacted by default]" },
        rawResponseData: null
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
          saml_request: "present",
          binding: idpMetadata.ssoBinding || "HTTP-Redirect"
        },
        responseData: {
          redirect_to: "IdP SSO endpoint",
          awaiting: "SAMLResponse on ACS"
        },
        rawRequestData: null,
        rawResponseData: null
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
          saml_response: samlResponseParam ? "present" : "missing"
        },
        responseData: null,
        rawRequestData: null,
        rawResponseData: null
      });

      if (!samlResponseParam) {
        samlFlowService.addFlowStep(runningFlow.id, {
          stepName: "saml_response_received",
          status: "error",
          completedAt: new Date().toISOString(),
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
          completedAt: new Date().toISOString(),
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
          size_bytes: samlResponseParam.length
        },
        responseData: { decoded: "success" },
        rawRequestData: { xml: "[SAMLResponse XML — redacted by default]" },
        rawResponseData: null
      });

      let parsed;
      try {
        parsed = parseSamlResponse(responseXml);
      } catch {
        samlFlowService.addFlowStep(runningFlow.id, {
          stepName: "saml_response_decoded",
          status: "error",
          completedAt: new Date().toISOString(),
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

      const attrCount = Object.keys(parsed.attributes || {}).length;
      samlFlowService.addFlowStep(runningFlow.id, {
        stepName: "saml_response_decoded",
        status: parsed.isSuccess ? "success" : "error",
        completedAt: new Date().toISOString(),
        requestData: {
          issuer: parsed.issuer || "(not found)",
          in_response_to: parsed.inResponseTo || "(not found)",
          destination: parsed.destination || "(not found)"
        },
        responseData: {
          status_code: parsed.statusCode || "(not found)",
          saml_status: parsed.isSuccess ? "Success" : "Failure",
          name_id: parsed.nameId || "(not present)",
          name_id_format: parsed.nameIdFormat || "(not present)",
          attributes_count: attrCount,
          ...(attrCount > 0 ? { attributes: parsed.attributes } : {})
        },
        rawResponseData: { xml: "[SAMLResponse XML — redacted by default]" },
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

      const newUiFlow = flowService.findRunningFlowByState(params.state || "", FLOW_STATE_TTL_MS);
      if (newUiFlow) {
        const completedFlow = await processNewUiCallback({ req, flow: newUiFlow, params });
        redirect(res, `/flows/${encodeURIComponent(completedFlow.id)}`);
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
