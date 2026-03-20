import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyzeTokens,
  buildCurlCommand,
  compareClaims,
  buildTokenExchangeRequest,
  buildUserInfoRequest,
  createBaseConfig,
  mergeDiscoveryIntoConfig,
  normalizeConfig,
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
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SERVER_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET || "";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomUUID();
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const SESSION_COOKIE = "oidc_debug_sid";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const STORAGE_DIR = process.env.STORAGE_DIR || path.join(projectRoot, "data");
const STATE_FILE = path.join(STORAGE_DIR, "state.json");

const staticFiles = new Map([
  ["/assets/app.css", { filePath: path.join(projectRoot, "public", "app.css"), contentType: "text/css; charset=utf-8" }],
  ["/assets/app.js", { filePath: path.join(projectRoot, "public", "app.js"), contentType: "application/javascript; charset=utf-8" }]
]);

const sessions = new Map();
let persistedDefaultConfig = createBaseConfig(BASE_URL);
let persistTimer = null;
let persistInFlight = Promise.resolve();
const logLevels = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

function configUsesClientSecret(config = {}) {
  return ["client_secret_basic", "client_secret_post"].includes(config.tokenEndpointAuthMethod);
}

function getTokenExchangeConfig(config = {}) {
  if (!configUsesClientSecret(config)) {
    return {
      ...config,
      clientSecret: ""
    };
  }

  if (!SERVER_CLIENT_SECRET) {
    throw new Error(
      "Le secret client doit etre configure cote serveur via `OIDC_CLIENT_SECRET` pour utiliser cette methode d'authentification /token."
    );
  }

  return {
    ...config,
    clientSecret: SERVER_CLIENT_SECRET
  };
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

function sanitizeSessionArtifacts(session) {
  return {
    ...session,
    config: normalizeConfig(session.config || {}, BASE_URL),
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

function createSession() {
  const id = crypto.randomBytes(24).toString("hex");
  return {
    id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    config: { ...persistedDefaultConfig },
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
    version: 1,
    updatedAt: new Date().toISOString(),
    defaultConfig: normalizeConfig(persistedDefaultConfig, BASE_URL),
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

async function loadPersistedState() {
  try {
    const raw = await readFile(STATE_FILE, "utf8");
    const parsed = JSON.parse(raw);

    if (parsed?.defaultConfig) {
      persistedDefaultConfig = normalizeConfig(parsed.defaultConfig, BASE_URL);
    }

    for (const candidate of parsed?.sessions || []) {
      if (!candidate?.id) {
        continue;
      }

      sessions.set(candidate.id, {
        id: candidate.id,
        createdAt: candidate.createdAt || new Date().toISOString(),
        updatedAt: candidate.updatedAt || new Date().toISOString(),
        config: normalizeConfig(candidate.config || persistedDefaultConfig, BASE_URL),
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
      sessions: sessions.size
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
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(sessionId).digest("hex").slice(0, 16);
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

  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(sessionId).digest("hex").slice(0, 16);
  if (signature.length !== expected.length) {
    return null;
  }
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)) ? sessionId : null;
}

function getOrCreateSession(req, res) {
  const cookies = parseCookies(req.headers.cookie || "");
  const raw = cookies[SESSION_COOKIE];
  const sessionId = decodeSessionCookie(raw);

  if (sessionId && sessions.has(sessionId)) {
    const session = sessions.get(sessionId);
    session.updatedAt = new Date().toISOString();
    schedulePersistState();
    return session;
  }

  const session = createSession();
  sessions.set(session.id, session);
  setSessionCookie(res, session.id);
  schedulePersistState();
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
  session.updatedAt = new Date().toISOString();
  persistedDefaultConfig = normalizeConfig(session.config, BASE_URL);
  schedulePersistState();
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

function resetFlowState(session, reason = "config_changed") {
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
  session.updatedAt = new Date().toISOString();
  schedulePersistState();

  addSessionLog(session, "info", "flow_reset", "Les etapes dependantes de la configuration ont ete reinitialisees.", {
    reason
  });
}

function configFingerprint(config) {
  return JSON.stringify(normalizeConfig(config, BASE_URL));
}

function applyConfigUpdate(session, nextConfig, reason) {
  const previousFingerprint = configFingerprint(session.config);
  const normalizedConfig = normalizeConfig(nextConfig, BASE_URL);
  const nextFingerprint = configFingerprint(normalizedConfig);

  session.config = normalizedConfig;
  persistedDefaultConfig = normalizedConfig;
  schedulePersistState();

  if (previousFingerprint !== nextFingerprint) {
    resetFlowState(session, reason);
    return true;
  }

  return false;
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

function currentPath(req) {
  return new URL(req.url, BASE_URL);
}

async function serveStatic(res, asset) {
  const content = await readFile(asset.filePath, "utf8");
  send(res, 200, content, asset.contentType);
}

function sanitizeSession(session, reveal = false) {
  const sanitized = sanitizeSessionArtifacts(session);

  if (!reveal) {
    return redactObject(sanitized);
  }

  return sanitized;
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

function inferActiveTab(pathname) {
  if (pathname === "/logs") {
    return "logs";
  }

  if (pathname === "/config") {
    return "configuration";
  }

  return "configuration";
}

function ensureHtmlSessionRoute(req) {
  return req.headers.accept?.includes("text/html") || req.headers.accept === "*/*" || !req.headers.accept;
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
      const flash = consumeFlash(session);
      sendHtml(
        res,
        renderPage({
          session,
          activeTab,
          baseUrl: BASE_URL,
          serverClientSecretConfigured: Boolean(SERVER_CLIENT_SECRET),
          flash
        })
      );
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

    if (req.method === "POST" && url.pathname === "/oidc/config/save") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const configChanged = applyConfigUpdate(session, body, "manual_config_update");

      addSessionLog(session, "info", "config_saved", "Configuration OIDC enregistree.", {
        config: session.config
      });

      if (body._action === "login") {
        redirect(res, "/oidc/login");
        return;
      }

      setFlash(
        session,
        "info",
        configChanged
          ? "Configuration mise a jour. Les etapes precedentes ont ete reinitialisees."
          : "Configuration mise a jour."
      );
      redirect(res, "/?tab=configuration");
      return;
    }

    if (req.method === "POST" && url.pathname === "/oidc/config/load-discovery") {
      const session = getOrCreateSession(req, res);
      const rawBody = await readBody(req);
      const body = parseBody(req, rawBody);
      const discoveryUrl = body.discoveryUrl || session.config.discoveryUrl;

      if (!discoveryUrl) {
        setFlash(session, "warn", "Discovery URL manquante.");
        redirect(res, "/?tab=configuration");
        return;
      }

      session.config.discoveryUrl = discoveryUrl;
      const requestSnapshot = {
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
      const responseSnapshot = await executeHttp(requestSnapshot);

      session.steps.discovery = {
        request: requestSnapshot,
        response: responseSnapshot
      };

      if (responseSnapshot.ok && Object.keys(responseSnapshot.parsed || {}).length > 0) {
        const mergedConfig = mergeDiscoveryIntoConfig(session.config, responseSnapshot.parsed);
        const configChanged = applyConfigUpdate(session, mergedConfig, "discovery_config_update");
        addSessionLog(session, "info", "discovery_loaded", "Configuration chargee depuis le discovery endpoint.", {
          discoveryUrl,
          response: responseSnapshot
        });
        setFlash(
          session,
          "info",
          configChanged
            ? "Discovery charge avec succes. Les etapes precedentes ont ete reinitialisees."
            : "Discovery charge avec succes."
        );
      } else {
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

    if (req.method === "GET" && url.pathname === "/oidc/login") {
      const session = getOrCreateSession(req, res);

      try {
        const prepared = prepareAuthorizationRequest(session.config);
        session.config = prepared.config;
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
        addSessionLog(session, "info", "authorize_request", "URL /authorize construite.", {
          request: prepared.request
        });
        redirect(res, prepared.request.url);
        return;
      } catch (error) {
        addSessionLog(session, "error", "authorize_request_failed", "Impossible de construire /authorize.", {
          error: error.message,
          config: session.config
        });
        setFlash(session, "error", error.message);
        redirect(res, "/?tab=authorize");
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
        const requestSnapshot = buildTokenExchangeRequest({
          config: getTokenExchangeConfig(session.config),
          code,
          codeVerifier: session.flow.codeVerifier
        });
        const responseSnapshot = await executeHttp(requestSnapshot);
        session.steps.token = {
          request: sanitizeTokenRequest(requestSnapshot),
          response: responseSnapshot
        };

        if (responseSnapshot.ok) {
          session.tokens = analyzeTokens(responseSnapshot.parsed || {});
          session.comparison = null;
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
          endpoint: session.config.userInfoEndpoint,
          accessToken
        });
        const responseSnapshot = await executeHttp(requestSnapshot);
        session.steps.userinfo = {
          request: requestSnapshot,
          response: responseSnapshot
        };

        if (responseSnapshot.ok) {
          const idTokenClaims = session.tokens?.idToken?.decoded?.payload || {};
          session.comparison = compareClaims(idTokenClaims, responseSnapshot.parsed || {});
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
        addSessionLog(session, "error", "userinfo_failed", "Impossible de preparer /userinfo.", {
          error: error.message
        });
        setFlash(session, "error", error.message);
      }

      redirect(res, "/?tab=userinfo");
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, {
        status: "ok",
        nodeEnv: NODE_ENV
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
  await loadPersistedState();
  server.listen(PORT, () => {
    appLog("info", "Serveur demarre", {
      port: PORT,
      baseUrl: BASE_URL,
      nodeEnv: NODE_ENV,
      logLevel: LOG_LEVEL,
      storageDir: STORAGE_DIR,
      stateFile: STATE_FILE,
      serverClientSecretConfigured: Boolean(SERVER_CLIENT_SECRET)
    });
  });
}

start().catch((error) => {
  appLog("error", "Impossible de demarrer le serveur", {
    error: error.message
  });
  process.exit(1);
});
