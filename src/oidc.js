import crypto from "node:crypto";

const SENSITIVE_TOKENS = [
  "access_token",
  "authorization",
  "client_secret",
  "code",
  "code_verifier",
  "id_token",
  "refresh_token",
  "token"
];

function isSensitiveKey(key = "") {
  const normalized = key.toLowerCase();
  return SENSITIVE_TOKENS.some((candidate) => normalized.includes(candidate));
}

export function createBaseConfig(baseUrl) {
  return {
    providerName: "",
    discoveryUrl: "",
    issuer: "",
    authorizationEndpoint: "",
    tokenEndpoint: "",
    userInfoEndpoint: "",
    jwksUri: "",
    clientId: "",
    clientSecret: "",
    clientType: "public",
    redirectUri: new URL("/oidc/callback", baseUrl).toString(),
    tokenEndpointAuthMethod: "none",
    responseType: "code",
    responseMode: "query",
    scopes: "openid profile email",
    state: "",
    nonce: "",
    pkceEnabled: true,
    codeChallengeMethod: "S256"
  };
}

function readBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    return ["1", "on", "true", "yes"].includes(value.toLowerCase());
  }

  return fallback;
}

function clean(value, fallback = "") {
  if (value === undefined || value === null) {
    return fallback;
  }

  return String(value).trim();
}

export function normalizeConfig(input = {}, baseUrl) {
  const defaults = createBaseConfig(baseUrl);
  const clientType = clean(input.clientType || defaults.clientType, defaults.clientType);
  const authMethod = clean(
    input.tokenEndpointAuthMethod || defaults.tokenEndpointAuthMethod,
    defaults.tokenEndpointAuthMethod
  );

  return {
    providerName: clean(input.providerName, defaults.providerName),
    discoveryUrl: clean(input.discoveryUrl, defaults.discoveryUrl),
    issuer: clean(input.issuer, defaults.issuer),
    authorizationEndpoint: clean(input.authorizationEndpoint, defaults.authorizationEndpoint),
    tokenEndpoint: clean(input.tokenEndpoint, defaults.tokenEndpoint),
    userInfoEndpoint: clean(input.userInfoEndpoint, defaults.userInfoEndpoint),
    jwksUri: clean(input.jwksUri, defaults.jwksUri),
    clientId: clean(input.clientId, defaults.clientId),
    clientSecret: "",
    clientType: ["public", "confidential"].includes(clientType) ? clientType : defaults.clientType,
    redirectUri: clean(input.redirectUri, defaults.redirectUri) || defaults.redirectUri,
    tokenEndpointAuthMethod: ["client_secret_basic", "client_secret_post", "none"].includes(authMethod)
      ? authMethod
      : defaults.tokenEndpointAuthMethod,
    responseType: clean(input.responseType, defaults.responseType) || defaults.responseType,
    responseMode: clean(input.responseMode, defaults.responseMode) || defaults.responseMode,
    scopes: clean(input.scopes, defaults.scopes) || defaults.scopes,
    state: clean(input.state, defaults.state),
    nonce: clean(input.nonce, defaults.nonce),
    pkceEnabled: readBoolean(input.pkceEnabled, defaults.pkceEnabled),
    codeChallengeMethod: clean(input.codeChallengeMethod, defaults.codeChallengeMethod) || defaults.codeChallengeMethod
  };
}

export function mergeDiscoveryIntoConfig(config, discovery = {}) {
  return {
    ...config,
    issuer: clean(discovery.issuer, config.issuer),
    authorizationEndpoint: clean(discovery.authorization_endpoint, config.authorizationEndpoint),
    tokenEndpoint: clean(discovery.token_endpoint, config.tokenEndpoint),
    userInfoEndpoint: clean(discovery.userinfo_endpoint, config.userInfoEndpoint),
    jwksUri: clean(discovery.jwks_uri, config.jwksUri)
  };
}

export function randomOpaque(length = 24) {
  return crypto.randomBytes(length).toString("hex");
}

export function generatePkcePair(method = "S256") {
  const verifier = base64UrlEncode(crypto.randomBytes(32));
  const challenge =
    method === "plain"
      ? verifier
      : base64UrlEncode(crypto.createHash("sha256").update(verifier).digest());

  return {
    codeVerifier: verifier,
    codeChallenge: challenge
  };
}

export function prepareAuthorizationRequest(config) {
  if (!config.authorizationEndpoint) {
    throw new Error("Authorization endpoint manquant.");
  }

  if (!config.clientId) {
    throw new Error("client_id manquant.");
  }

  if (!config.redirectUri) {
    throw new Error("redirect_uri manquant.");
  }

  if (config.responseType !== "code") {
    throw new Error("V1 ne supporte que le Authorization Code Flow (`response_type=code`).");
  }

  if (config.responseMode === "fragment") {
    throw new Error("`response_mode=fragment` n'est pas supporte par ce backend.");
  }

  const state = config.state || randomOpaque(12);
  const nonce = config.nonce || randomOpaque(12);
  const runtime = {
    state,
    nonce,
    codeVerifier: "",
    codeChallenge: ""
  };

  const effectiveConfig = {
    ...config,
    state,
    nonce
  };

  const params = {
    client_id: effectiveConfig.clientId,
    redirect_uri: effectiveConfig.redirectUri,
    response_type: effectiveConfig.responseType,
    scope: effectiveConfig.scopes,
    state,
    nonce
  };

  if (effectiveConfig.responseMode) {
    params.response_mode = effectiveConfig.responseMode;
  }

  if (effectiveConfig.pkceEnabled) {
    const pair = generatePkcePair(effectiveConfig.codeChallengeMethod);
    runtime.codeVerifier = pair.codeVerifier;
    runtime.codeChallenge = pair.codeChallenge;
    params.code_challenge = pair.codeChallenge;
    params.code_challenge_method = effectiveConfig.codeChallengeMethod;
  }

  const search = serializeForm(params);
  const url = `${effectiveConfig.authorizationEndpoint}?${search}`;

  return {
    config: effectiveConfig,
    runtime,
    request: {
      url,
      method: "GET",
      headers: {},
      params,
      body: "",
      redactedBody: "",
      curl: ""
    }
  };
}

export function buildTokenExchangeRequest({ config, code, codeVerifier }) {
  if (!config.tokenEndpoint) {
    throw new Error("Token endpoint manquant.");
  }

  if (!config.clientId) {
    throw new Error("client_id manquant.");
  }

  if (!code) {
    throw new Error("Authorization code manquant.");
  }

  const headers = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json"
  };

  const bodyParams = {
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri
  };

  if (config.pkceEnabled && codeVerifier) {
    bodyParams.code_verifier = codeVerifier;
  }

  if (config.tokenEndpointAuthMethod === "client_secret_basic") {
    if (!config.clientSecret) {
      throw new Error("client_secret requis pour `client_secret_basic`.");
    }

    const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`, "utf8").toString("base64");
    headers.authorization = `Basic ${basic}`;
  } else if (config.tokenEndpointAuthMethod === "client_secret_post") {
    if (!config.clientSecret) {
      throw new Error("client_secret requis pour `client_secret_post`.");
    }

    bodyParams.client_id = config.clientId;
    bodyParams.client_secret = config.clientSecret;
  } else {
    bodyParams.client_id = config.clientId;
  }

  const body = serializeForm(bodyParams);

  return {
    url: config.tokenEndpoint,
    method: "POST",
    headers,
    body,
    redactedBody: redactBodyText(body, headers["content-type"]),
    params: bodyParams,
    curl: buildCurlCommand({
      url: config.tokenEndpoint,
      method: "POST",
      headers,
      body
    })
  };
}

export function buildUserInfoRequest({ endpoint, accessToken }) {
  if (!endpoint) {
    throw new Error("UserInfo endpoint manquant.");
  }

  if (!accessToken) {
    throw new Error("Access token manquant.");
  }

  const headers = {
    accept: "application/json",
    authorization: `Bearer ${accessToken}`
  };

  return {
    url: endpoint,
    method: "GET",
    headers,
    body: "",
    redactedBody: "",
    params: {},
    curl: buildCurlCommand({
      url: endpoint,
      method: "GET",
      headers
    })
  };
}

export function serializeForm(values = {}) {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(values)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    params.set(key, String(value));
  }

  return params.toString();
}

function base64UrlEncode(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64").toString("utf8");
}

export function safeJsonParse(text) {
  if (!text || typeof text !== "string") {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function decodeJwt(token) {
  if (!token || typeof token !== "string") {
    return {
      isJwt: false,
      error: "Token absent."
    };
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    return {
      isJwt: false,
      error: "Le token n'a pas le format JWT."
    };
  }

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));

    return {
      isJwt: true,
      header,
      payload
    };
  } catch (error) {
    return {
      isJwt: false,
      error: `JWT illisible: ${error.message}`
    };
  }
}

function computeExpiration(token, fallbackExpiresIn) {
  const decoded = decodeJwt(token);

  if (decoded.isJwt && decoded.payload?.exp) {
    return {
      source: "claim exp",
      epochSeconds: decoded.payload.exp,
      iso: new Date(decoded.payload.exp * 1000).toISOString()
    };
  }

  if (fallbackExpiresIn) {
    const epochSeconds = Math.floor(Date.now() / 1000) + Number(fallbackExpiresIn);
    return {
      source: "expires_in",
      epochSeconds,
      iso: new Date(epochSeconds * 1000).toISOString()
    };
  }

  return null;
}

function tokenFormat(token) {
  if (!token) {
    return "absent";
  }

  return token.split(".").length === 3 ? "JWT" : "opaque";
}

export function analyzeTokens(tokenResponse = {}) {
  const accessToken = clean(tokenResponse.access_token);
  const idToken = clean(tokenResponse.id_token);
  const refreshToken = clean(tokenResponse.refresh_token);

  return {
    accessToken: {
      value: accessToken,
      maskedValue: maskSensitiveValue("access_token", accessToken),
      format: tokenFormat(accessToken),
      decoded: decodeJwt(accessToken),
      expiration: computeExpiration(accessToken, tokenResponse.expires_in)
    },
    idToken: {
      value: idToken,
      maskedValue: maskSensitiveValue("id_token", idToken),
      format: tokenFormat(idToken),
      decoded: decodeJwt(idToken),
      expiration: computeExpiration(idToken)
    },
    refreshToken: {
      present: Boolean(refreshToken),
      value: refreshToken,
      maskedValue: maskSensitiveValue("refresh_token", refreshToken)
    },
    raw: tokenResponse
  };
}

export function compareClaims(idTokenClaims = {}, userInfoClaims = {}) {
  const onlyInIdToken = [];
  const onlyInUserInfo = [];
  const differing = [];

  const idKeys = new Set(Object.keys(idTokenClaims || {}));
  const userInfoKeys = new Set(Object.keys(userInfoClaims || {}));

  for (const key of idKeys) {
    if (!userInfoKeys.has(key)) {
      onlyInIdToken.push(key);
      continue;
    }

    const left = JSON.stringify(idTokenClaims[key]);
    const right = JSON.stringify(userInfoClaims[key]);

    if (left !== right) {
      differing.push({
        key,
        idToken: idTokenClaims[key],
        userInfo: userInfoClaims[key]
      });
    }
  }

  for (const key of userInfoKeys) {
    if (!idKeys.has(key)) {
      onlyInUserInfo.push(key);
    }
  }

  return {
    onlyInIdToken,
    onlyInUserInfo,
    differing
  };
}

export function redactBodyText(bodyText, contentType = "") {
  if (!bodyText) {
    return "";
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const parsed = Object.fromEntries(new URLSearchParams(bodyText).entries());
    return serializeForm(redactObject(parsed));
  }

  if (contentType.includes("application/json")) {
    const parsed = safeJsonParse(bodyText);
    if (parsed) {
      return JSON.stringify(redactObject(parsed), null, 2);
    }
  }

  return bodyText;
}

export function redactHeaders(headers = {}) {
  const clone = {};

  for (const [key, value] of Object.entries(headers)) {
    clone[key] = isSensitiveKey(key) ? maskSensitiveValue(key, value) : value;
  }

  return clone;
}

export function redactObject(value, parentKey = "") {
  if (Array.isArray(value)) {
    return value.map((item) => redactObject(item, parentKey));
  }

  if (value && typeof value === "object") {
    const clone = {};

    for (const [key, nested] of Object.entries(value)) {
      clone[key] = redactObject(nested, key);
    }

    return clone;
  }

  if (typeof value === "string" && isSensitiveKey(parentKey)) {
    return maskSensitiveValue(parentKey, value);
  }

  return value;
}

export function maskSensitiveValue(key, value) {
  if (value === undefined || value === null || value === "") {
    return "";
  }

  const text = String(value);

  if (!isSensitiveKey(key)) {
    return text;
  }

  if (text.length <= 10) {
    return "********";
  }

  return `${text.slice(0, 6)}...${text.slice(-4)}`;
}

export function shellEscape(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`;
}

export function buildCurlCommand({ url, method = "GET", headers = {}, body = "" }) {
  const parts = ["curl", "-i", "-X", method.toUpperCase(), shellEscape(url)];

  for (const [key, value] of Object.entries(headers)) {
    parts.push("-H", shellEscape(`${key}: ${value}`));
  }

  if (body) {
    parts.push("--data-raw", shellEscape(body));
  }

  return parts.join(" ");
}

export function toPrettyJson(value) {
  if (value === null || value === undefined || value === "") {
    return "";
  }

  return JSON.stringify(value, null, 2);
}
