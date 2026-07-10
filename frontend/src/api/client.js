const DEFAULT_TIMEOUT_MS = 8000;
const ACTION_TIMEOUT_MS = 15000;

async function fetchJson(path, { timeoutMs = DEFAULT_TIMEOUT_MS, method = "GET", body = null } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = { accept: "application/json" };
    let payload;
    if (body !== null && body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }

    const response = await fetch(path, {
      signal: controller.signal,
      method,
      headers,
      body: payload,
      credentials: "same-origin"
    });

    const contentType = response.headers.get("content-type") || "";
    if (!contentType.toLowerCase().includes("application/json")) {
      const error = new Error(`Unexpected content type: ${contentType || "(none)"}`);
      error.status = response.status;
      throw error;
    }

    let responseBody = null;
    try {
      responseBody = await response.json();
    } catch {
      const error = new Error("Response is not valid JSON.");
      error.status = response.status;
      throw error;
    }

    if (!response.ok) {
      const message = responseBody && typeof responseBody.error === "string"
        ? responseBody.error
        : `HTTP ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      if (responseBody && responseBody.fieldErrors && typeof responseBody.fieldErrors === "object") {
        error.fieldErrors = responseBody.fieldErrors;
      }
      if (responseBody && Array.isArray(responseBody.warnings)) {
        error.warnings = responseBody.warnings;
      }
      throw error;
    }

    return responseBody;
  } catch (error) {
    if (error.name === "AbortError") {
      const timeoutError = new Error(`Request timed out after ${timeoutMs} ms.`);
      timeoutError.cause = "timeout";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function getHealth() {
  return fetchJson("/api/health");
}

export function getOidcServiceProviders() {
  return fetchJson("/api/oidc/service-providers");
}

export function getOidcServiceProvider(id) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/oidc/service-providers/${safeId}`);
}

export function getOidcEnvironments() {
  return fetchJson("/api/oidc/environments");
}

export function getOidcFlows() {
  return fetchJson("/api/oidc/flows");
}

export function getOidcFlow(id) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/oidc/flows/${safeId}`);
}

export function getSamlServiceProviders() {
  return fetchJson("/api/saml/service-providers");
}

export function getSamlServiceProvider(id) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/saml/service-providers/${safeId}`);
}

export function getSamlFlows() {
  return fetchJson("/api/saml/flows");
}

export function getSamlFlow(id) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/saml/flows/${safeId}`);
}

// Action helpers.
// Payloads are never logged nor stored — the caller is expected to consume
// `redirectUrl` immediately via window.location.assign and drop the response.
function postAction(path) {
  return fetchJson(path, { method: "POST", timeoutMs: ACTION_TIMEOUT_MS });
}

export function startOidcFlow(spId) {
  const safeId = encodeURIComponent(String(spId || ""));
  return postAction(`/api/oidc/flows/start/${safeId}`);
}

export function rerunOidcFlow(flowId) {
  const safeId = encodeURIComponent(String(flowId || ""));
  return postAction(`/api/oidc/flows/${safeId}/rerun`);
}

export function startSamlFlow(spId) {
  const safeId = encodeURIComponent(String(spId || ""));
  return postAction(`/api/saml/flows/start/${safeId}`);
}

export function rerunSamlFlow(flowId) {
  const safeId = encodeURIComponent(String(flowId || ""));
  return postAction(`/api/saml/flows/${safeId}/rerun`);
}

// Write helpers.
// The client_secret is transmitted only inside the JSON body of a same-origin
// POST/PATCH and is dropped as soon as the request settles — never stored,
// never logged.
export function createOidcServiceProvider(payload) {
  return fetchJson("/api/oidc/service-providers", {
    method: "POST",
    body: payload,
    timeoutMs: ACTION_TIMEOUT_MS
  });
}

export function updateOidcServiceProvider(id, payload) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/oidc/service-providers/${safeId}`, {
    method: "PATCH",
    body: payload,
    timeoutMs: ACTION_TIMEOUT_MS
  });
}

export function deleteOidcServiceProvider(id) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/oidc/service-providers/${safeId}`, {
    method: "DELETE",
    timeoutMs: ACTION_TIMEOUT_MS
  });
}

export function createSamlServiceProvider(payload) {
  return fetchJson("/api/saml/service-providers", {
    method: "POST",
    body: payload,
    timeoutMs: ACTION_TIMEOUT_MS
  });
}

export function updateSamlServiceProvider(id, payload) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/saml/service-providers/${safeId}`, {
    method: "PATCH",
    body: payload,
    timeoutMs: ACTION_TIMEOUT_MS
  });
}

export function deleteSamlServiceProvider(id) {
  const safeId = encodeURIComponent(String(id || ""));
  return fetchJson(`/api/saml/service-providers/${safeId}`, {
    method: "DELETE",
    timeoutMs: ACTION_TIMEOUT_MS
  });
}
