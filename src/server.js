import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyzeTokens,
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
let persistTimer = null;
let persistInFlight = Promise.resolve();
let runtimeSessionSecret = process.env.SESSION_SECRET || "";
let runtimeSecretSource = process.env.SESSION_SECRET ? "env" : "pending";
let secretKey = null;
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

  return {
    ...normalized,
    scopes: normalized.scopes,
    secretConfigured: Boolean(serviceProvider.secretRecord?.ciphertext),
    createdAt: serviceProvider.createdAt || null,
    updatedAt: serviceProvider.updatedAt || null
  };
}

function sortServiceProviders(entries = []) {
  return [...entries].sort((left, right) => left.name.localeCompare(right.name, "fr"));
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
        appLog("error", "Echec de persistance de l'etat applicatif", {
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
      appLog("error", "Echec de persistance de l'etat applicatif", {
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
    sessions: []
  };
}

async function loadPersistedState() {
  try {
    const raw = await readFile(STATE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    const hydrated = parsed?.version === 2 ? parsed : migrateLegacyState(parsed);

    providerConfig = sanitizeProviderConfig(hydrated.providerConfig);
    serviceProviders = sortServiceProviders(
      (hydrated.serviceProviders || []).map((entry) => {
        const normalized = normalizeServiceProvider(entry, entry);

        return {
          id: normalized.id || createId("sp"),
          name: normalized.name,
          clientId: normalized.clientId,
          clientType: normalized.clientType,
          scopes: normalized.scopes,
          secretRecord: entry.secretRecord || null,
          createdAt: entry.createdAt || new Date().toISOString(),
          updatedAt: entry.updatedAt || new Date().toISOString()
        };
      })
    );

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
      serviceProviders: serviceProviders.length
    });
  } catch (error) {
    if (error.code === "ENOENT") {
      appLog("info", "Aucun etat persiste trouve, demarrage avec etat vide", {
        stateFile: STATE_FILE
      });
      return;
    }

    appLog("error", "Impossible de charger l'etat persiste", {
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
  return serviceProviders.find((entry) => entry.id === serviceProviderId) || null;
}

function resolveSelectedServiceProvider(session) {
  const selected = getServiceProvider(session.selectedServiceProviderId);
  if (selected) {
    return selected;
  }

  if (!serviceProviders.length) {
    return null;
  }

  return serviceProviders[0];
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
  const existing = input.id ? getServiceProvider(input.id) : null;
  const normalized = normalizeServiceProvider(input, existing || {});
  const now = new Date().toISOString();
  const isNew = !existing;
  const next = {
    id: normalized.id || createId("sp"),
    name: normalized.name,
    clientId: normalized.clientId,
    clientType: normalized.clientType,
    scopes: normalized.scopes,
    secretRecord:
      normalized.clientType === "confidential"
        ? existing?.secretRecord || null
        : null,
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };

  if (normalized.clientType === "confidential" && rawSecret) {
    next.secretRecord = encryptSecret(rawSecret);
  }

  if (existing) {
    serviceProviders = serviceProviders.map((entry) => (entry.id === existing.id ? next : entry));
  } else {
    serviceProviders = [...serviceProviders, next];
  }

  serviceProviders = sortServiceProviders(serviceProviders);
  schedulePersistState();

  return {
    serviceProvider: next,
    isNew,
    secretUpdated: Boolean(normalized.clientType === "confidential" && rawSecret)
  };
}

function removeServiceProvider(serviceProviderId) {
  const before = serviceProviders.length;
  serviceProviders = serviceProviders.filter((entry) => entry.id !== serviceProviderId);

  for (const session of sessions.values()) {
    if (session.selectedServiceProviderId === serviceProviderId) {
      session.selectedServiceProviderId = "";
      resetFlowState(session, "service_provider_deleted");
    }
  }

  schedulePersistState();
  return serviceProviders.length !== before;
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

async function serveStatic(res, asset) {
  const content = await readFile(asset.filePath, "utf8");
  send(res, 200, content, asset.contentType);
}

function sanitizeSession(session, reveal = false) {
  const sanitized = sanitizeSessionArtifacts(session);
  const payload = {
    ...sanitized,
    providerConfig: sanitizeProviderConfig(providerConfig),
    serviceProviders: serviceProviders.map(sanitizeServiceProviderForUi)
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
    return "Le endpoint cible utilise localhost/127.0.0.1. Depuis Docker, cela designe le conteneur lui-meme, pas l'hote ni l'IdP.";
  }

  if (code === "ENOTFOUND") {
    return "Le nom DNS du token endpoint n'est pas resolu depuis le conteneur.";
  }

  if (code === "ECONNREFUSED") {
    return "La connexion TCP est refusee. Le service cible n'ecoute probablement pas sur cet hote/port.";
  }

  if (code === "ECONNRESET") {
    return "La connexion a ete interrompue par le serveur ou un equipement intermediaire.";
  }

  if (code === "ETIMEDOUT" || causeMessage.toLowerCase().includes("timeout")) {
    return "Le endpoint ne repond pas dans le delai attendu. Il peut etre injoignable ou filtre.";
  }

  if (causeMessage.toLowerCase().includes("certificate") || causeMessage.toLowerCase().includes("self-signed")) {
    return "Le handshake TLS a echoue. Le certificat du serveur n'est probablement pas reconnu par Node dans le conteneur.";
  }

  if (causeMessage.toLowerCase().includes("ssl") || causeMessage.toLowerCase().includes("tls")) {
    return "Le handshake TLS a echoue. Verifie le certificat, la chaine de confiance et l'URL https ciblee.";
  }

  return "Erreur reseau basse couche avant toute reponse HTTP. Verifie l'URL, la resolution DNS, l'accessibilite reseau et TLS.";
}

function formatFetchError(error, request) {
  const cause = error?.cause || null;
  const details = {
    name: error?.name || "Error",
    message: error?.message || "Erreur fetch inconnue.",
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
        ? `Impossible de charger le well-known: ${responseSnapshot.error}`
        : `Le well-known a retourne ${responseSnapshot.status || "une erreur inconnue"}.`
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
    throw new Error("Aucune configuration Service Provider disponible.");
  }

  const secret = selected.clientType === "confidential" ? decryptSecret(selected.secretRecord) : "";

  if (selected.clientType === "confidential" && !secret) {
    throw new Error("Aucun secret configure pour ce Service Provider confidentiel.");
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
    serviceProviders: serviceProviders.map(sanitizeServiceProviderForUi),
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

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/config" || url.pathname === "/logs")) {
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
          error: "Session introuvable."
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

      addSessionLog(session, "info", "provider_saved", "Configuration provider enregistree.", {
        providerConfig
      });
      setFlash(
        session,
        "info",
        changed
          ? "Configuration provider mise a jour. Le test courant a ete reinitialise."
          : "Configuration provider mise a jour."
      );
      redirect(res, "/?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/provider/load-discovery") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const discoveryUrl = body.discoveryUrl || providerConfig.discoveryUrl;

      if (!discoveryUrl) {
        setFlash(session, "warn", "Discovery URL manquante.");
        redirect(res, "/?tab=configuration");
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
        addSessionLog(session, "info", "discovery_loaded", "Well-known verifie avec succes.", {
          discoveryUrl,
          response: responseSnapshot
        });
        setFlash(session, "info", "Well-known verifie avec succes.");
      } else {
        touchSession(session);
        addSessionLog(session, "warn", "discovery_failed", "Echec du chargement du discovery endpoint.", {
          discoveryUrl,
          response: responseSnapshot
        });
        setFlash(
          session,
          "warn",
          responseSnapshot.error
            ? `Erreur reseau sur le discovery endpoint: ${responseSnapshot.error}`
            : `Discovery endpoint en echec (${responseSnapshot.status || "inconnu"}).`
        );
      }

      redirect(res, "/?tab=configuration");
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

      addSessionLog(session, "info", "service_provider_saved", "Configuration Service Provider enregistree.", {
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
          ? "Service Provider cree."
          : secretUpdated
            ? "Service Provider mis a jour. Le secret a ete remplace."
            : "Service Provider mis a jour."
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
        setFlash(session, "warn", "Service Provider introuvable.");
        redirect(res, "/?tab=configuration");
        return;
      }

      addSessionLog(session, "info", "service_provider_deleted", "Configuration Service Provider supprimee.", {
        serviceProviderId
      });
      setFlash(session, "info", "Service Provider supprime.");
      redirect(res, "/?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers/select") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const selected = getServiceProvider(body.id || "");

      if (!selected) {
        setFlash(session, "warn", "Service Provider introuvable.");
        redirect(res, "/?tab=configuration");
        return;
      }

      const changed = session.selectedServiceProviderId !== selected.id;
      session.selectedServiceProviderId = selected.id;

      if (changed) {
        resetFlowState(session, "service_provider_selected");
      } else {
        touchSession(session);
      }

      setFlash(session, "info", `Service Provider selectionne: ${selected.name || selected.clientId}.`);
      redirect(res, "/?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/service-providers/test") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const selected = getServiceProvider(body.id || "");

      if (!selected) {
        setFlash(session, "warn", "Service Provider introuvable.");
        redirect(res, "/?tab=configuration");
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
        redirect(res, "/?tab=configuration");
        return;
      }
    }

    if ((req.method === "GET" || req.method === "POST") && url.pathname === "/oidc/callback") {
      const session = getOrCreateSession(req, res);
      const rawBody = req.method === "POST" ? await readBody(req) : "";
      const body = req.method === "POST" ? parseBody(req, rawBody) : {};
      const params = req.method === "POST" ? body : Object.fromEntries(url.searchParams.entries());
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

      redirect(res, "/?tab=callback");
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
          setFlash(session, "info", "Echange /token termine.");
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
        addSessionLog(session, "error", "token_exchange_failed", "Echec de la preparation de la requete /token.", {
          error: error.message
        });
        setFlash(session, "error", error.message);
      }

      redirect(res, "/?tab=token");
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
          addSessionLog(session, "info", "userinfo_loaded", "Endpoint /userinfo appele avec succes.", {
            response: responseSnapshot
          });
          setFlash(session, "info", "Appel /userinfo termine.");
        } else {
          addSessionLog(session, "warn", "userinfo_failed", "Le endpoint /userinfo a repondu en erreur.", {
            response: responseSnapshot
          });
          setFlash(
            session,
            "warn",
            responseSnapshot.error
              ? `Erreur reseau sur /userinfo: ${responseSnapshot.error}`
              : `Le endpoint /userinfo a retourne ${responseSnapshot.status}.`
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
        addSessionLog(session, "error", "userinfo_failed", "Impossible de preparer /userinfo.", {
          error: error.message
        });
        setFlash(session, "error", error.message);
      }

      redirect(res, "/?tab=userinfo");
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      const currentProviderConfig = sanitizeProviderConfig(providerConfig);
      sendJson(res, 200, {
        status: "ok",
        nodeEnv: NODE_ENV,
        redirectUri: currentProviderConfig.redirectUri,
        serviceProviders: serviceProviders.length
      });
      return;
    }

    if (ensureHtmlSessionRoute(req)) {
      const session = getOrCreateSession(req, res);
      setFlash(session, "warn", `Route inconnue: ${url.pathname}`);
      redirect(res, "/");
      return;
    }

    sendJson(res, 404, {
      error: "Route introuvable."
    });
  } catch (error) {
    appLog("error", "Erreur non geree", {
      error: error.message,
      path: url.pathname
    });
    sendJson(res, 500, {
      error: "Erreur interne.",
      detail: error.message
    });
  }
});

async function shutdown(signal) {
  appLog("info", "Arret du serveur, persistance de l'etat", { signal });
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
    appLog("warn", "BASE_URL absent: utilisation de RENDER_EXTERNAL_URL comme URL publique.", {
      renderExternalUrl: RENDER_EXTERNAL_URL,
      redirectUri: createProviderConfig().redirectUri
    });
  }

  if (IS_RENDER && !process.env.STORAGE_DIR) {
    appLog("warn", "STORAGE_DIR absent sur Render: utilisation de /app/storage. Verifier qu'un persistent disk est bien monte sur ce chemin.", {
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
      serviceProviders: serviceProviders.length
    });
  });
}

start().catch((error) => {
  appLog("error", "Impossible de demarrer le serveur", {
    error: error.message
  });
  process.exit(1);
});
