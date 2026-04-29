import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getEzAccessEnvironment, listEzAccessEnvironments } from "./config.js";
import {
  analyzeTokens,
  decodeJwt,
  buildCurlCommand,
  buildEffectiveConfig,
  buildTokenExchangeRequest,
  buildUserInfoRequest,
  compareClaims,
  createProviderConfig,
  FIXED_REDIRECT_URI,
  mergeDiscoveryIntoProviderConfig,
  normalizeProviderConfig,
  normalizeServiceProvider,
  prepareAuthorizationRequest,
  redactBodyText,
  redactObject,
  safeJsonParse
} from "./oidc.js";
import { renderPage } from "./render.js";
import { createFlowService, STEP_ORDER } from "./services/flows.js";
import { createServiceProviderService, isServiceProviderReady, serviceProviderStatus } from "./services/serviceProviders.js";
import { renderDashboard } from "./views/dashboard.js";
import { renderFlowDetailsPage } from "./views/flowDetails.js";
import { renderFlowResultPage } from "./views/flowResult.js";
import { renderServiceProvidersPage } from "./views/serviceProviders.js";
import { renderServiceProviderEditPage } from "./views/serviceProviderEdit.js";
import { renderServiceProviderNewPage } from "./views/serviceProviderNew.js";
import { renderLogsPage } from "./views/logs.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const RENDER_EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL || "";
const IS_RENDER = process.env.RENDER === "true" || Boolean(RENDER_EXTERNAL_URL);
const BASE_URL = process.env.BASE_URL || RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const SESSION_COOKIE = "oidc_debug_sid";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const STORAGE_DIR = process.env.STORAGE_DIR || (IS_RENDER ? "/app/storage" : path.join(projectRoot, "data"));
const STATE_FILE = path.join(STORAGE_DIR, "state.json");
const SESSION_SECRET_FILE = path.join(STORAGE_DIR, "session-secret");

const staticFiles = new Map([
  ["/assets/app.css", { filePath: path.join(projectRoot, "public", "app.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/app.js", { filePath: path.join(projectRoot, "public", "app.js"), contentType: "application/javascript; charset=utf-8" }]
]);

const sessions = new Map();
let providerConfig = createProviderConfig();
let serviceProviders = [];
let flows = [];
let flowSteps = [];
let persistTimer = null;
let persistInFlight = Promise.resolve();
let runtimeSessionSecret = process.env.SESSION_SECRET || "";
let runtimeSecretSource = process.env.SESSION_SECRET ? "env" : "pending";
let secretKey = null;
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
const logLevels = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

function getSessionSecret() {
  if (!runtimeSessionSecret) {
    throw new Error("SESSION_SECRET non initialise.");
  }

  return runtimeSessionSecret;
}

function getSecretKey() {
  if (!secretKey) {
    throw new Error("Cle de chiffrement non initialisee.");
  }

  return secretKey;
}

function createId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function encryptSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getSecretKey(), iv);
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

  const decipher = crypto.createDecipheriv(
    record.algorithm || "aes-256-gcm",
    getSecretKey(),
    Buffer.from(record.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(record.tag, "base64"));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
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
    }
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
    version: 2,
    updatedAt: new Date().toISOString(),
    providerConfig: sanitizeProviderConfig(providerConfig),
    serviceProviders,
    flows,
    flowSteps,
    sessions: Array.from(sessions.values()).map((session) => ({
      ...sanitizeSessionArtifacts(session),
      flash: null
    }))
  };
}

async function persistStateNow() {
  await mkdir(STORAGE_DIR, { recursive: true });
  const tempFile = `${STATE_FILE}.tmp`;
  await writeFile(tempFile, JSON.stringify(buildPersistedState(), null, 2), "utf8");
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

function migrateLegacyState(parsed = {}) {
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

async function loadPersistedState() {
  try {
    const raw = await readFile(STATE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    const hydrated = parsed?.version === 2 ? parsed : migrateLegacyState(parsed);

    providerConfig = sanitizeProviderConfig(hydrated.providerConfig);
    serviceProviderService.hydrateServiceProviders(hydrated.serviceProviders || []);
    flowService.hydrateFlows(hydrated.flows || [], hydrated.flowSteps || []);

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
      serviceProviders: serviceProviders.length,
      flows: flows.length
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

async function ensureRuntimeSecrets() {
  if (process.env.SESSION_SECRET) {
    runtimeSessionSecret = process.env.SESSION_SECRET;
    runtimeSecretSource = "env";
    secretKey = crypto.createHash("sha256").update(runtimeSessionSecret).digest();
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

  secretKey = crypto.createHash("sha256").update(runtimeSessionSecret).digest();
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
  const signature = crypto.createHmac("sha256", getSessionSecret()).update(sessionId).digest("hex").slice(0, 16);
  const value = `${sessionId}.${signature}`;
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax`);
}

function decodeSessionCookie(rawValue = "") {
  if (!rawValue) {
    return null;
  }

  const [sessionId, signature] = rawValue.split(".");
  if (!sessionId || !signature) {
    return null;
  }

  const expected = crypto.createHmac("sha256", getSessionSecret()).update(sessionId).digest("hex").slice(0, 16);
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

function getSessionById(id) {
  return sessions.get(id) || null;
}

function addSessionLog(session, level, event, message, data = null) {
  session.logs.push({
    id: crypto.randomBytes(6).toString("hex"),
    time: new Date().toISOString(),
    level,
    event,
    message,
    data: data ? redactObject(data) : null
  });
  touchSession(session);
  appLog(level, message, { event, ...(data || {}) });
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

function resolveSelectedServiceProvider(session) {
  const selected = getServiceProvider(session.selectedServiceProviderId);
  if (selected) {
    return selected;
  }

  if (!serviceProviders.length) {
    return null;
  }

  return serviceProviderService.listServiceProviders()[0];
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

function applyProviderConfigUpdate(nextConfig) {
  const previous = JSON.stringify(providerConfig);
  const normalized = sanitizeProviderConfig({
    ...providerConfig,
    ...nextConfig
  });
  providerConfig = normalized;
  schedulePersistState();
  return previous !== JSON.stringify(normalized);
}

function upsertServiceProvider(input, rawSecret) {
  return serviceProviderService.upsertServiceProvider(input, rawSecret);
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

  for await (const chunk of req) {
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

function send(res, statusCode, body, contentType) {
  res.writeHead(statusCode, {
    "content-type": contentType
  });
  res.end(body);
}

function sendHtml(res, html) {
  send(res, 200, html, "text/html; charset=utf-8");
}

function sendJson(res, statusCode, payload) {
  send(res, statusCode, JSON.stringify(payload, null, 2), "application/json; charset=utf-8");
}

function redirect(res, location) {
  res.writeHead(302, {
    location
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

async function serveStatic(res, asset) {
  const content = await readFile(asset.filePath, "utf8");
  send(res, 200, content, asset.contentType);
}

function sanitizeSession(session, reveal = false) {
  const sanitized = sanitizeSessionArtifacts(session);
  const payload = {
    ...sanitized,
    providerConfig: sanitizeProviderConfig(providerConfig),
    serviceProviders: serviceProviderService.listServiceProviders().map(sanitizeServiceProviderForUi)
  };

  if (!reveal) {
    return redactObject(payload);
  }

  return payload;
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

async function resolveProviderConfigForRun() {
  const baseConfig = sanitizeProviderConfig(providerConfig);

  if (!baseConfig.discoveryUrl) {
    return {
      config: baseConfig,
      discovery: null
    };
  }

  const requestSnapshot = buildDiscoveryRequest(baseConfig.discoveryUrl);
  const responseSnapshot = await executeHttp(requestSnapshot);

  if (!responseSnapshot.ok || Object.keys(responseSnapshot.parsed || {}).length === 0) {
    throw new Error(
      responseSnapshot.error
        ? `Unable to load the well-known: ${responseSnapshot.error}`
        : `The well-known returned ${responseSnapshot.status || "an unknown error"}.`
    );
  }

  return {
    config: mergeDiscoveryIntoProviderConfig(baseConfig, responseSnapshot.parsed),
    discovery: {
      request: requestSnapshot,
      response: responseSnapshot
    }
  };
}

function inferActiveTab(pathname) {
  if (pathname === "/logs") {
    return "logs";
  }

  return "configuration";
}

function ensureHtmlSessionRoute(req) {
  return req.headers.accept?.includes("text/html") || req.headers.accept === "*/*" || !req.headers.accept;
}

async function buildRunConfig(session, serviceProviderId, redirectUri = "") {
  const selected = getServiceProvider(serviceProviderId) || resolveSelectedServiceProvider(session);

  if (!selected) {
    throw new Error("No Service Provider configuration available.");
  }

  const secret = selected.clientType === "confidential" ? decryptSecret(selected.secretRecord) : "";

  if (selected.clientType === "confidential" && !secret) {
    throw new Error("No secret configured for this confidential Service Provider.");
  }

  session.selectedServiceProviderId = selected.id;

  const resolvedProvider =
    session.runtimeContext?.serviceProviderId === selected.id &&
    session.runtimeContext?.authorizationEndpoint &&
    session.runtimeContext?.tokenEndpoint
      ? sanitizeProviderConfig({
          providerName: session.runtimeContext.providerName,
          discoveryUrl: session.runtimeContext.discoveryUrl,
          issuer: session.runtimeContext.issuer,
          authorizationEndpoint: session.runtimeContext.authorizationEndpoint,
          tokenEndpoint: session.runtimeContext.tokenEndpoint,
          userInfoEndpoint: session.runtimeContext.userInfoEndpoint,
          jwksUri: session.runtimeContext.jwksUri,
          redirectUri: session.runtimeContext.redirectUri
        })
      : (await resolveProviderConfigForRun()).config;

  const effectiveRedirectUri = redirectUri || resolvedProvider.redirectUri || FIXED_REDIRECT_URI;

  return {
    selected,
    config: buildEffectiveConfig({
      providerConfig: resolvedProvider,
      serviceProvider: selected,
      clientSecret: secret,
      redirectUri: effectiveRedirectUri
    }),
    provider: resolvedProvider
  };
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

    const startFlowServiceProviderId = req.method === "POST" ? matchFlowStartPath(url.pathname) : null;
    if (startFlowServiceProviderId) {
      const session = getOrCreateSession(req, res);
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

    if (req.method === "GET" && url.pathname === "/logs") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "logs", url);
      sendHtml(res, renderLogsPage(model));
      return;
    }

    // Legacy debug view kept temporarily for backend compatibility. Not used by the new UI.
    if (req.method === "GET" && url.pathname === "/config") {
      const session = getOrCreateSession(req, res);
      const activeTab = routeTab(url) || inferActiveTab(url.pathname);
      sendHtml(res, renderPage(buildPageModel(session, activeTab, url)));
      return;
    }

    if (req.method === "GET" && url.pathname.startsWith("/oidc/session/")) {
      const sessionId = decodeURIComponent(url.pathname.replace("/oidc/session/", ""));
      const session = getSessionById(sessionId);

      if (!session) {
        sendJson(res, 404, {
          error: "Session not found."
        });
        return;
      }

      sendJson(res, 200, sanitizeSession(session, url.searchParams.get("reveal") === "1"));
      return;
    }

    if (req.method === "POST" && url.pathname === "/provider/save") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const changed = applyProviderConfigUpdate(body);

      if (changed) {
        resetFlowState(session, "provider_config_update");
      }

        addSessionLog(session, "info", "provider_saved", "Provider configuration saved.", {
        providerConfig
      });
      setFlash(
        session,
        "info",
        changed
            ? "Provider configuration updated. The current test has been reset."
            : "Provider configuration updated."
      );
      redirect(res, "/config?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/provider/load-discovery") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const discoveryUrl = body.discoveryUrl || providerConfig.discoveryUrl;

      if (!discoveryUrl) {
        setFlash(session, "warn", "Discovery URL missing.");
        redirect(res, "/config?tab=configuration");
        return;
      }

      const changed = applyProviderConfigUpdate({
        discoveryUrl
      });
      const requestSnapshot = buildDiscoveryRequest(discoveryUrl);
      const responseSnapshot = await executeHttp(requestSnapshot);

      session.steps.discovery = {
        request: requestSnapshot,
        response: responseSnapshot
      };

      if (responseSnapshot.ok && Object.keys(responseSnapshot.parsed || {}).length > 0) {
        if (changed) {
          resetFlowState(session, "discovery_url_update");
        } else {
          touchSession(session);
        }
        addSessionLog(session, "info", "discovery_loaded", "Well-known verified successfully.", {
          discoveryUrl,
          response: responseSnapshot
        });
        setFlash(session, "info", "Well-known verified successfully.");
      } else {
        touchSession(session);
        addSessionLog(session, "warn", "discovery_failed", "Discovery endpoint load failed.", {
          discoveryUrl,
          response: responseSnapshot
        });
        setFlash(
          session,
          "warn",
          responseSnapshot.error
            ? `Network error on the discovery endpoint: ${responseSnapshot.error}`
            : `Discovery endpoint failed (${responseSnapshot.status || "unknown"}).`
        );
      }

      redirect(res, "/config?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers/save") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const secret = String(body.clientSecret || "").trim();
      const { serviceProvider, isNew, secretUpdated } = upsertServiceProvider(body, secret);

      if (session.selectedServiceProviderId === serviceProvider.id || !session.selectedServiceProviderId) {
        session.selectedServiceProviderId = serviceProvider.id;
        resetFlowState(session, "service_provider_update");
      } else {
        touchSession(session);
      }

        addSessionLog(session, "info", "service_provider_saved", "Service Provider configuration saved.", {
        serviceProvider: sanitizeServiceProviderForUi(serviceProvider),
        secretUpdated
      });

      if (body._action === "saveAndTest") {
        redirect(res, `/oidc/login?sp=${encodeURIComponent(serviceProvider.id)}`);
        return;
      }

      setFlash(
        session,
        "info",
        isNew
          ? "Service Provider created."
          : secretUpdated
            ? "Service Provider updated. The secret has been replaced."
            : "Service Provider updated."
      );
      redirect(res, `/?tab=configuration&edit=${encodeURIComponent(serviceProvider.id)}`);
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers/delete") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const serviceProviderId = body.id || "";

      if (!serviceProviderId || !removeServiceProvider(serviceProviderId)) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/config?tab=configuration");
        return;
      }

      addSessionLog(session, "info", "service_provider_deleted", "Service Provider configuration deleted.", {
        serviceProviderId
      });
      setFlash(session, "info", "Service Provider deleted.");
      redirect(res, "/config?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers/select") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const selected = getServiceProvider(body.id || "");

      if (!selected) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/config?tab=configuration");
        return;
      }

      const changed = session.selectedServiceProviderId !== selected.id;
      session.selectedServiceProviderId = selected.id;

      if (changed) {
        resetFlowState(session, "service_provider_selected");
      } else {
        touchSession(session);
      }

      setFlash(session, "info", `Service Provider selected: ${selected.name || selected.clientId}.`);
      redirect(res, "/config?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers/test") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const selected = getServiceProvider(body.id || "");

      if (!selected) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/config?tab=configuration");
        return;
      }

      session.selectedServiceProviderId = selected.id;
      touchSession(session);
      redirect(res, `/oidc/login?sp=${encodeURIComponent(selected.id)}`);
      return;
    }

    if (req.method === "GET" && url.pathname === "/oidc/login") {
      const session = getOrCreateSession(req, res);
      const requestedServiceProviderId = url.searchParams.get("sp") || session.selectedServiceProviderId;

      try {
        const runConfig = await buildRunConfig(session, requestedServiceProviderId);
        const prepared = prepareAuthorizationRequest(runConfig.config);
        session.runtimeContext = {
          providerName: runConfig.provider.providerName,
          discoveryUrl: runConfig.provider.discoveryUrl,
          issuer: runConfig.provider.issuer,
          authorizationEndpoint: runConfig.provider.authorizationEndpoint,
          tokenEndpoint: runConfig.provider.tokenEndpoint,
          userInfoEndpoint: runConfig.provider.userInfoEndpoint,
          jwksUri: runConfig.provider.jwksUri,
          redirectUri: runConfig.config.redirectUri,
          serviceProviderId: runConfig.selected.id,
          serviceProviderName: runConfig.selected.name,
          clientId: runConfig.selected.clientId,
          clientType: runConfig.selected.clientType,
          scopes: runConfig.selected.scopes,
          tokenEndpointAuthMethod: prepared.config.tokenEndpointAuthMethod
        };
        session.flow.expectedState = prepared.runtime.state;
        session.flow.expectedNonce = prepared.runtime.nonce;
        session.flow.codeVerifier = prepared.runtime.codeVerifier;
        session.flow.codeChallenge = prepared.runtime.codeChallenge;
        session.steps.authorize = {
          requestedAt: new Date().toISOString(),
          request: prepared.request,
          response: {
            status: 302,
            headers: {
              location: prepared.request.url
            },
            body: "",
            redactedBody: "",
            parsed: null
          }
        };
        session.steps.callback = null;
        session.steps.token = null;
        session.steps.userinfo = null;
        session.tokens = null;
        session.comparison = null;
        touchSession(session);
        addSessionLog(session, "info", "authorize_request", "URL /authorize construite.", {
          request: prepared.request,
          serviceProvider: sanitizeServiceProviderForUi(runConfig.selected)
        });
        redirect(res, prepared.request.url);
        return;
      } catch (error) {
        addSessionLog(session, "error", "authorize_request_failed", "Impossible de construire /authorize.", {
          error: error.message,
          providerConfig,
          serviceProvider: sanitizeServiceProviderForUi(getServiceProvider(requestedServiceProviderId))
        });
        setFlash(session, "error", error.message);
        redirect(res, "/config?tab=configuration");
        return;
      }
    }

    if ((req.method === "GET" || req.method === "POST") && url.pathname === "/oidc/callback") {
      const session = getOrCreateSession(req, res);
      const rawBody = req.method === "POST" ? await readBody(req) : "";
      const body = req.method === "POST" ? parseBody(req, rawBody) : {};
      const params = req.method === "POST" ? body : Object.fromEntries(url.searchParams.entries());

      const newUiFlow = flowService.findRunningFlowByState(params.state || "");
      if (newUiFlow) {
        const completedFlow = await processNewUiCallback({ req, flow: newUiFlow, params });
        redirect(res, `/flows/${encodeURIComponent(completedFlow.id)}`);
        return;
      }

      const stateCheck = evaluateState(session.flow.expectedState, params.state);

      session.steps.callback = {
        receivedAt: new Date().toISOString(),
        method: req.method,
        params,
        raw: req.method === "POST" ? rawBody : url.searchParams.toString(),
        stateCheck
      };
      touchSession(session);

      const level = params.error ? "error" : stateCheck === "mismatch" ? "warn" : "info";
      addSessionLog(
        session,
        level,
        "callback_received",
        params.error ? "Callback OIDC recu avec erreur." : "Callback OIDC recu.",
        {
          callback: session.steps.callback
        }
      );

      if (params.error) {
        setFlash(session, "error", `${params.error}: ${params.error_description || "erreur renvoyee par le provider."}`);
      } else if (stateCheck === "mismatch") {
        setFlash(session, "warn", "Le state recu ne correspond pas a la valeur attendue.");
      } else if (stateCheck === "missing") {
        setFlash(session, "warn", "Le callback ne contient pas de state.");
      } else {
        setFlash(session, "info", "Callback OIDC recu.");
      }

      redirect(res, "/config?tab=callback");
      return;
    }

    if (req.method === "POST" && url.pathname === "/oidc/token/exchange") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const code = body.code || session.steps.callback?.params?.code;

      try {
        const runConfig = await buildRunConfig(
          session,
          session.runtimeContext?.serviceProviderId || session.selectedServiceProviderId,
          session.runtimeContext?.redirectUri || ""
        );
        const requestSnapshot = buildTokenExchangeRequest({
          config: runConfig.config,
          code,
          codeVerifier: session.flow.codeVerifier
        });
        const responseSnapshot = await executeHttp(requestSnapshot);
        session.steps.token = {
          request: sanitizeTokenRequest(requestSnapshot),
          response: responseSnapshot
        };
        touchSession(session);

        if (responseSnapshot.ok) {
          session.tokens = analyzeTokens(responseSnapshot.parsed || {});
          session.comparison = null;
          touchSession(session);
          addSessionLog(session, "info", "token_exchanged", "Authorization code echange contre des tokens.", {
            response: responseSnapshot
          });
          setFlash(session, "info", "/token exchange completed.");
        } else {
          addSessionLog(session, "warn", "token_exchange_failed", "Le token endpoint a repondu en erreur.", {
            response: responseSnapshot
          });
          setFlash(
            session,
            "warn",
            responseSnapshot.error
              ? `Erreur reseau sur /token: ${responseSnapshot.error}`
              : `Le token endpoint a retourne ${responseSnapshot.status}.`
          );
        }
      } catch (error) {
        session.steps.token = {
          request: null,
          response: {
            status: 0,
            headers: {},
            body: "",
            redactedBody: "",
            parsed: null,
            error: error.message
          }
        };
        touchSession(session);
        addSessionLog(session, "error", "token_exchange_failed", "Failed to prepare the /token request.", {
          error: error.message
        });
        setFlash(session, "error", error.message);
      }

      redirect(res, "/config?tab=token");
      return;
    }

    if (req.method === "POST" && url.pathname === "/oidc/userinfo") {
      const session = getOrCreateSession(req, res);
      const accessToken = session.tokens?.accessToken?.value || session.steps.token?.response?.parsed?.access_token;

      try {
        const requestSnapshot = buildUserInfoRequest({
          endpoint: session.runtimeContext?.userInfoEndpoint || providerConfig.userInfoEndpoint,
          accessToken
        });
        const responseSnapshot = await executeHttp(requestSnapshot);
        session.steps.userinfo = {
          request: requestSnapshot,
          response: responseSnapshot
        };
        touchSession(session);

        if (responseSnapshot.ok) {
          const idTokenClaims = session.tokens?.idToken?.decoded?.payload || {};
          session.comparison = compareClaims(idTokenClaims, responseSnapshot.parsed || {});
          touchSession(session);
          addSessionLog(session, "info", "userinfo_loaded", "The /userinfo endpoint was called successfully.", {
            response: responseSnapshot
          });
          setFlash(session, "info", "The /userinfo call completed.");
        } else {
          addSessionLog(session, "warn", "userinfo_failed", "The /userinfo endpoint returned an error.", {
            response: responseSnapshot
          });
          setFlash(
            session,
            "warn",
            responseSnapshot.error
                ? `Network error on /userinfo: ${responseSnapshot.error}`
                : `/userinfo returned ${responseSnapshot.status}.`
          );
        }
      } catch (error) {
        session.steps.userinfo = {
          request: null,
          response: {
            status: 0,
            headers: {},
            body: "",
            redactedBody: "",
            parsed: null,
            error: error.message
          }
        };
        touchSession(session);
        addSessionLog(session, "error", "userinfo_failed", "Unable to prepare /userinfo.", {
          error: error.message
        });
        setFlash(session, "error", error.message);
      }

      redirect(res, "/config?tab=userinfo");
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      const currentProviderConfig = sanitizeProviderConfig(providerConfig);
      sendJson(res, 200, {
        status: "ok",
        nodeEnv: NODE_ENV,
        redirectUri: currentProviderConfig.redirectUri,
        serviceProviders: serviceProviders.length,
        flows: flows.length
      });
      return;
    }

    if (ensureHtmlSessionRoute(req)) {
      const session = getOrCreateSession(req, res);
      setFlash(session, "warn", `Unknown route: ${url.pathname}`);
      redirect(res, "/");
      return;
    }

    sendJson(res, 404, {
      error: "Route not found."
    });
  } catch (error) {
    appLog("error", "Unhandled error", {
      error: error.message,
      path: url.pathname
    });
    sendJson(res, 500, {
      error: "Internal error.",
      detail: error.message
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
      serviceProviders: serviceProviders.length,
      flows: flows.length
    });
  });
}

start().catch((error) => {
  appLog("error", "Impossible de demarrer le serveur", {
    error: error.message
  });
  process.exit(1);
});
