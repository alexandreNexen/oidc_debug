import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

function formatDate(v) {
  return v ? new Date(v).toLocaleString("fr-FR") : "Not available";
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "Running";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function encodeRawData(value) {
  if (!value || (typeof value === "object" && Object.keys(value).length === 0)) return "";
  return Buffer.from(JSON.stringify(value, null, 2), "utf8").toString("base64");
}

// ---- Status badge helpers ----

const BADGE_SUCCESS = new Set(["yes", "received", "present", "sent", "valid", "success", "match", "ok", "received / redacted", "prepared", "available", "received and decoded", "readable"]);
const BADGE_ERROR = new Set(["no", "missing", "failed", "mismatch", "error", "failure", "invalid", "expired"]);
const BADGE_NEUTRAL = new Set(["not implemented", "not checked", "not extracted", "skipped", "none",
  "disabled", "not sent", "pending", "not performed", "not available", "unavailable", "incomplete", "not_checked"]);

const PERSONAL_CLAIMS = new Set(["email", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "phone_number", "address", "birthdate", "locale", "zoneinfo", "picture", "website", "profile", "nonce"]);
const COLLECTION_CLAIMS = new Set(["roles", "role", "groups", "group", "authorities", "entitlements", "realm_access", "resource_access"]);
const PUBLIC_PROTOCOL_CLAIMS = new Set(["iss", "aud", "azp", "exp", "iat", "nbf", "auth_time", "acr", "amr", "typ", "token_type"]);

function badge(value) {
  if (value === null || value === undefined || value === "") return `<span class="muted">—</span>`;
  if (typeof value === "number") {
    const str = String(value);
    if (value >= 200 && value < 300) return `<span class="badge badge--success">${str}</span>`;
    if (value >= 400) return `<span class="badge badge--error">${str}</span>`;
    return `<span>${str}</span>`;
  }
  const str = String(value);
  const low = str.toLowerCase().trim();

  if (BADGE_SUCCESS.has(low)
    || low.includes("generated + sent")
    || low.includes("challenge sent")
    || low.includes("sent via")
    || (low.includes("masked") && !low.startsWith("error"))
    || (low.includes("received") && (low.includes("sent") || low.includes("masked")))) {
    return `<span class="badge badge--success">${escapeHtml(str)}</span>`;
  }
  if (BADGE_ERROR.has(low) || low.startsWith("missing") || (low.startsWith("error") && low.length > 5)) {
    return `<span class="badge badge--error">${escapeHtml(str)}</span>`;
  }
  if (BADGE_NEUTRAL.has(low)
    || low.includes("not implemented")
    || low.includes("not checked")
    || low.includes("not extracted")
    || low.includes("not performed")) {
    return `<span class="badge badge--neutral">${escapeHtml(str)}</span>`;
  }
  const n = Number(str.trim());
  if (Number.isFinite(n) && str.trim() !== "") {
    if (n >= 200 && n < 300) return `<span class="badge badge--success">${escapeHtml(str)}</span>`;
    if (n >= 400) return `<span class="badge badge--error">${escapeHtml(str)}</span>`;
  }
  return `<span>${escapeHtml(str)}</span>`;
}

function plain(v) {
  if (v === null || v === undefined || v === "") return `<span class="muted">—</span>`;
  return `<span>${escapeHtml(String(v))}</span>`;
}

function muted(v) {
  if (v === null || v === undefined || v === "") return "";
  return `<p class="muted" style="margin:6px 0 0">${escapeHtml(String(v))}</p>`;
}

// ---- Layout helpers ----

function dl(rows) {
  const filtered = rows.filter(Boolean);
  if (!filtered.length) return `<p class="muted">No data available.</p>`;
  return `<dl class="flow-data-list">${filtered.join("")}</dl>`;
}

function row(label, html) {
  return `<div class="flow-data-list__row"><dt>${escapeHtml(label)}</dt><dd>${html}</dd></div>`;
}

function statusWithDetail(status, detail) {
  return `${badge(status)}${detail ? muted(detail) : ""}`;
}

function pkceSummary(value) {
  const str = String(value || "");
  if (!str || str === "disabled") return str || "disabled";
  if (/s256/i.test(str)) return "S256";
  return str.replace(/\s*challenge sent\s*/i, "").trim() || str;
}

function providerErrorSummary(callbackResponse = {}) {
  if (!callbackResponse.error && callbackResponse.provider_error !== "received") return badge("none");
  const detail = [
    callbackResponse.error ? `OAuth error: ${callbackResponse.error}` : "",
    callbackResponse.error_description ? `error_description: ${callbackResponse.error_description}` : ""
  ].filter(Boolean).join("; ");
  return statusWithDetail("error", detail);
}

function callbackStatus(callbackStep) {
  if (!callbackStep) return "missing";
  return callbackStep.status === "success" || callbackStep.status === "error" ? "received" : "missing";
}

function tokenExchangeStatus(tokenStep, response = {}) {
  if (!tokenStep || tokenStep.status === "pending") return "";
  if (tokenStep.status === "success" && response.token_error === "none") return "success";
  return "failed";
}

function tokenFailureDetail(response = {}) {
  if (!response.token_error || response.token_error === "none") return "";
  return [
    response.http_status ? `HTTP status: ${response.http_status}` : "",
    `OAuth error: ${response.token_error}`,
    response.error_description ? `error_description: ${response.error_description}` : ""
  ].filter(Boolean).join("; ");
}

function claimsListSummary(claims = [], { max = 8 } = {}) {
  if (!Array.isArray(claims) || claims.length === 0) return "";
  const visible = claims.slice(0, max);
  const suffix = claims.length > max ? `, +${claims.length - max} more` : "";
  return `${visible.join(", ")}${suffix}`;
}

function scopesFromFlow(flow = {}, steps = []) {
  const auth = steps.find((s) => s.stepName === "authorize");
  const source = flow.runtime?.scopes || flow.scopes || auth?.requestData?.scope || "";
  return String(source).split(/\s+/).map((scope) => scope.trim()).filter(Boolean);
}

function claimEntriesFromObject(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value).filter(([claim]) => claim && !["claims", "raw_claims_available"].includes(claim));
}

function idTokenClaimEntries(tokenStep = {}) {
  const payload = tokenStep.rawAnalysisData?.jwt?.payload;
  if (payload && typeof payload === "object") return claimEntriesFromObject(payload);

  const diag = tokenStep.responseData?.id_token_diagnostics || {};
  return claimEntriesFromObject({
    iss: diag.issuer,
    aud: diag.audience,
    sub: diag.subject,
    exp: diag.expiration
  });
}

function userInfoClaimEntries(userInfoStep = {}) {
  const claims = userInfoStep.rawResponseData?.body?.claims;
  if (claims && typeof claims === "object") return claimEntriesFromObject(claims);

  const receivedClaims = userInfoStep.responseData?.received_claims;
  if (Array.isArray(receivedClaims) && receivedClaims.length > 0) {
    return receivedClaims.map((claim) => [claim, claim === "sub" ? userInfoStep.responseData?.subject || "received / redacted" : "received / redacted"]);
  }

  return userInfoStep.responseData?.subject ? [["sub", userInfoStep.responseData.subject]] : [];
}

function formatClaimValue(claim, value) {
  if (value === null || value === undefined || value === "") return "missing";
  const name = String(claim || "").toLowerCase();

  if (PERSONAL_CLAIMS.has(name)) return "received / redacted";
  if (name === "sub") return "received / redacted";

  if (Array.isArray(value)) {
    if (COLLECTION_CLAIMS.has(name)) return `${value.length} value${value.length > 1 ? "s" : ""}`;
    return value.map((item) => String(item)).join(", ");
  }

  if (typeof value === "object") {
    const keys = Object.keys(value);
    return `${keys.length} nested field${keys.length > 1 ? "s" : ""}`;
  }

  if (typeof value === "string" && value.length > 80) {
    return `${value.slice(0, 77)}...`;
  }

  return PUBLIC_PROTOCOL_CLAIMS.has(name) ? String(value) : "received / redacted";
}

function claimTable(entries = [], emptyLabel = "Unavailable") {
  if (!entries.length) return `<p class="muted">${escapeHtml(emptyLabel)}</p>`;
  return `
    <div class="table-scroll">
      <table class="table table--compact">
        <thead>
          <tr><th>Claim</th><th>Value</th></tr>
        </thead>
        <tbody>
          ${entries.map(([claim, value]) => `
            <tr>
              <td><code class="code-inline">${escapeHtml(String(claim))}</code></td>
              <td>${escapeHtml(formatClaimValue(claim, value))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>`;
}

function scopesList(scopes = []) {
  if (!scopes.length) return `<span class="muted">Unavailable</span>`;
  return scopes.map((scope) => `<span class="badge badge--neutral">${escapeHtml(scope)}</span>`).join(" ");
}

function userInfoStatus(step) {
  if (!step || step.status === "pending") return "";
  if (step.status === "skipped") return "skipped";
  return step.status === "success" ? "success" : "failed";
}

function userInfoFailureDetail(response = {}) {
  if (!response.error || response.error === "none") return "";
  return [
    response.http_status ? `HTTP status: ${response.http_status}` : "",
    `error: ${response.error}`,
    response.error_description ? `error_description: ${response.error_description}` : ""
  ].filter(Boolean).join("; ");
}

function oidcChecksResult(checks = {}) {
  const values = Object.values(checks).filter(Boolean);
  if (values.length === 0) return "not_checked";
  if (values.some((value) => ["invalid", "expired", "missing"].includes(String(value)))) return "failed";
  return "passed";
}

function cleanIdTokenAnalysisRaw(rawData) {
  if (!rawData || typeof rawData !== "object" || Array.isArray(rawData)) return rawData;

  const cleaned = {
    ...rawData,
    jwt: rawData.jwt && typeof rawData.jwt === "object"
      ? {
          ...rawData.jwt,
          header: rawData.jwt.header && typeof rawData.jwt.header === "object" ? { ...rawData.jwt.header } : rawData.jwt.header,
          payload: rawData.jwt.payload && typeof rawData.jwt.payload === "object" ? { ...rawData.jwt.payload } : rawData.jwt.payload
        }
      : rawData.jwt
  };

  if (rawData.validation && typeof rawData.validation === "object") {
    const { signature: _signature, ...validation } = rawData.validation;
    if (validation.overall === "incomplete") {
      const checks = {
        issuer: validation.issuer,
        audience: validation.audience,
        expiration: validation.expiration,
        nonce: validation.nonce
      };
      validation.overall = oidcChecksResult(checks);
    }
    cleaned.validation = validation;
  }

  if (rawData.checks && typeof rawData.checks === "object") {
    const { signature: _signature, ...checks } = rawData.checks;
    if (checks.result === "incomplete") {
      checks.result = oidcChecksResult({
        issuer: checks.issuer,
        audience: checks.audience,
        expiration: checks.expiration,
        nonce: checks.nonce
      });
    }
    cleaned.checks = checks;
  }

  return cleaned;
}

function idTokenAnalysisChecks(rawData = {}, diagnostics = {}) {
  const rawValidation = rawData?.checks || rawData?.validation || {};
  const checks = {
    issuer: rawValidation.issuer || diagnostics.issuer_validation || "",
    audience: rawValidation.audience || diagnostics.audience_validation || "",
    expiration: rawValidation.expiration || diagnostics.expiration_validation || "",
    nonce: rawValidation.nonce || diagnostics.nonce_validation || ""
  };
  const rawResult = rawValidation.result || rawValidation.overall || diagnostics.overall_validation || "";
  return {
    ...checks,
    result: rawResult && rawResult !== "incomplete" ? rawResult : oidcChecksResult(checks)
  };
}

function rawBtn(title, stepName, type, rawData) {
  if (!rawData) return "";
  const label = type === "request" ? "Request" : "Response";
  return `<button class="panel-action-button" type="button"
    data-raw-open
    data-raw-title="${escapeHtml(title)}"
    data-raw-step="${escapeHtml(stepName)}"
    data-raw-type="${escapeHtml(label)}"
    data-raw-json="${escapeHtml(encodeRawData(rawData))}"
  >Raw</button>`;
}

function sectionHead(title, summary) {
  return `
    <div class="flow-section__header">
      <h2 class="flow-section__title">${escapeHtml(title)}</h2>
      <p class="flow-section__summary">${escapeHtml(summary)}</p>
    </div>`;
}

function exchangePanel(title, rawButton, content, errorMsg) {
  return `
    <article class="flow-detail-panel">
      <header>
        <h3>${escapeHtml(title)}</h3>
        ${rawButton}
      </header>
      ${content}
      ${errorMsg ? `<div class="form-banner form-banner--error" style="margin-top:12px">${escapeHtml(String(errorMsg))}</div>` : ""}
    </article>`;
}

// ---- Section navigation ----

function sectionDot(status) {
  const cls = status === "success" ? "section-tab__dot--success"
    : status === "error" ? "section-tab__dot--error"
    : status === "running" ? "section-tab__dot--running"
    : "";
  return `<span class="section-tab__dot${cls ? ` ${cls}` : ""}" aria-hidden="true"></span>`;
}

function renderSectionNav(tabs) {
  return `
    <nav class="section-tabs" data-section-nav aria-label="Flow sections">
      ${tabs.map((tab, i) => `
        ${i > 0 ? `<span class="section-tabs__sep" aria-hidden="true">→</span>` : ""}
        <button
          class="section-tab${i === 0 ? " is-active" : ""}"
          type="button"
          data-section-tab="${escapeHtml(tab.id)}"
          aria-selected="${i === 0 ? "true" : "false"}"
        >
          <span class="section-tab__num">${tab.num}</span>
          ${escapeHtml(tab.label)}
          ${sectionDot(tab.status)}
        </button>
      `).join("")}
    </nav>`;
}

function computeSectionTabs(steps) {
  const byName = new Map(steps.map((s) => [s.stepName, s]));
  const auth = byName.get("authorize");
  const cb = byName.get("callback");
  const token = byName.get("token");
  const ui = byName.get("userinfo");

  let authStatus = "pending";
  if (auth?.status === "error" || cb?.status === "error") authStatus = "error";
  else if (cb?.status === "success") authStatus = "success";
  else if (auth?.status === "success") authStatus = "running";

  const tokenStatus = token?.status || "pending";
  const uiStatus = ui?.status || "pending";

  const idTokenStatus = token?.status === "error" ? "error"
    : token?.status === "success" ? "success"
    : "pending";

  return [
    { id: "authorization", label: "Authorization", num: 1, status: authStatus },
    { id: "token-exchange", label: "Token exchange", num: 2, status: tokenStatus },
    { id: "userinfo", label: "UserInfo", num: 3, status: uiStatus },
    { id: "scopes-claims", label: "Scopes & Claims", num: 4, status: idTokenStatus }
  ];
}

// ---- Section 1: Authorization ----

function renderAuthorization(steps) {
  const auth = steps.find((s) => s.stepName === "authorize");
  const cb = steps.find((s) => s.stepName === "callback");
  const rd = auth?.requestData || {};
  const cbrd = cb?.responseData || {};
  const authPending = !auth || auth.status === "pending";

  const requestContent = authPending
    ? `<p class="muted">Not started.</p>`
    : dl([
        row("Authorization request", badge("prepared")),
        row("Flow type", plain("authorization_code")),
        row("PKCE", badge(pkceSummary(rd.pkce))),
        row("Scopes", plain(rd.scope))
      ]);

  const stateDetail = cbrd.state_validation && cbrd.state_validation !== "valid"
    ? `Expected state did not match callback state.`
    : "";
  const callbackDetail = !cb && !authPending ? "The browser has not returned to the callback yet." : "";
  const responseContent = !cb
    ? `<p class="muted">${authPending ? "Not started." : "Waiting for callback…"}</p>`
    : dl([
        row("Callback", statusWithDetail(callbackStatus(cb), callbackDetail)),
        row("State validation", statusWithDetail(cbrd.state_validation, stateDetail)),
        row("Provider error", providerErrorSummary(cbrd))
      ]);

  return `
    <section class="flow-section" data-section-panel="authorization">
      ${sectionHead("Authorization", "The SP prepares an authorization request to the IdP. The IdP redirects the user back to the callback with an authorization code.")}
      <div class="exchange-grid">
        ${exchangePanel("Request",
          rawBtn("Raw Authorization Request", "authorize", "request", auth?.rawRequestData),
          requestContent,
          auth?.errorData?.errorDescription)}
        ${exchangePanel("Callback received",
          rawBtn("Sanitized Callback Received", "callback", "response", cb?.rawResponseData || cb?.rawRequestData),
          responseContent,
          cb?.errorData?.errorDescription)}
      </div>
    </section>`;
}

// ---- Section 2: Token exchange ----

function renderTokenExchange(steps) {
  const token = steps.find((s) => s.stepName === "token");
  const rd = token?.requestData || {};
  const resp = token?.responseData || {};
  const notReached = !token || token.status === "pending";

  const requestContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : dl([
        row("Token request", badge("sent")),
        row("Client authentication", plain(rd.client_authentication_method))
      ]);

  const tokenError = resp.token_error && resp.token_error !== "none";
  const responseContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : dl([
        row("Token exchange", statusWithDetail(tokenExchangeStatus(token, resp), tokenFailureDetail(resp))),
        row("HTTP status", badge(resp.http_status != null ? String(resp.http_status) : "")),
        row("Access token", badge(resp.access_token)),
        row("ID token", badge(resp.id_token)),
        row("Refresh token", badge(resp.refresh_token)),
        resp.expires_in != null && resp.expires_in !== "" ? row("Expires in", plain(`${resp.expires_in} s`)) : null,
        tokenError ? row("OAuth error", statusWithDetail(resp.token_error, resp.error_description)) : null
      ]);

  return `
    <section class="flow-section" data-section-panel="token-exchange">
      ${sectionHead("Token exchange", "The SP exchanges the authorization code for tokens at the token endpoint.")}
      <div class="exchange-grid">
        ${exchangePanel("Request",
          rawBtn("Raw Token Request", "token", "request", token?.rawRequestData),
          requestContent,
          null)}
        ${exchangePanel("Response",
          rawBtn("Raw Token Response", "token", "response", token?.rawResponseData),
          responseContent,
          token?.errorData?.errorDescription)}
      </div>
    </section>`;
}

// ---- Section 3: UserInfo ----

function renderUserInfo(steps) {
  const ui = steps.find((s) => s.stepName === "userinfo");
  const rd = ui?.requestData || {};
  const resp = ui?.responseData || {};
  const notReached = !ui || ui.status === "pending";
  const skipped = ui?.status === "skipped";
  const receivedClaims = Array.isArray(resp.received_claims) ? resp.received_claims : (resp.subject ? ["sub"] : []);

  const requestContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : dl([
        row("UserInfo request", statusWithDetail(
          skipped ? "skipped" : "sent",
          skipped ? (resp.skipped_reason || "UserInfo request skipped.") : ""
        ))
      ]);

  const uiError = resp.error && resp.error !== "none";
  const responseContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : skipped
    ? dl([
        row("UserInfo", statusWithDetail("skipped", resp.skipped_reason || "No reason provided.")),
        row("User identified", badge("no")),
        row("Subject", badge("missing")),
        row("Claims", badge("missing"))
      ])
    : dl([
        row("UserInfo", statusWithDetail(userInfoStatus(ui), userInfoFailureDetail(resp))),
        uiError ? row("HTTP status", badge(resp.http_status != null ? String(resp.http_status) : "")) : null,
        row("User identified", badge(resp.subject ? "yes" : "no")),
        row("Subject", resp.subject ? plain(resp.subject) : badge("missing")),
        row("Claims", badge(resp.raw_claims_available === "yes" ? "available" : "missing")),
        receivedClaims.length ? row("Claims received", plain(claimsListSummary(receivedClaims))) : null,
        uiError ? row("Error", statusWithDetail(resp.error, resp.error_description)) : null
      ]);

  return `
    <section class="flow-section" data-section-panel="userinfo">
      ${sectionHead("UserInfo", "The SP uses the access token to retrieve user information from the IdP.")}
      <div class="exchange-grid">
        ${exchangePanel("Request",
          rawBtn("Raw UserInfo Request", "userinfo", "request", ui?.rawRequestData),
          requestContent,
          null)}
        ${exchangePanel("Response",
          rawBtn("Raw UserInfo Response", "userinfo", "response", ui?.rawResponseData),
          responseContent,
          ui?.errorData?.errorDescription)}
      </div>
    </section>`;
}

// ---- Section 4: Scopes & Claims ----

function renderScopesAndClaims(flow, steps) {
  const token = steps.find((s) => s.stepName === "token");
  const diag = token?.responseData?.id_token_diagnostics;
  const analysisRaw = cleanIdTokenAnalysisRaw(token?.rawAnalysisData || null);
  const rawButton = rawBtn("Raw ID Token Analysis", "token", "response", analysisRaw);
  const userInfo = steps.find((s) => s.stepName === "userinfo");
  const userInfoRawButton = rawBtn("Raw UserInfo Response", "userinfo", "response", userInfo?.rawResponseData);
  const scopes = scopesFromFlow(flow, steps);
  const idTokenClaims = idTokenClaimEntries(token);
  const userInfoClaims = userInfoClaimEntries(userInfo);
  const analysisChecks = idTokenAnalysisChecks(analysisRaw, diag);
  const idTokenState = !token || token.status === "pending"
    ? "Not reached."
    : !diag || diag.id_token_received === "no"
      ? "No ID token received."
      : "";
  const userInfoState = !userInfo || userInfo.status === "pending"
    ? "Not requested."
    : userInfo.status === "skipped"
      ? "Not requested."
      : userInfo.status === "error"
        ? "Request failed."
        : "";

  return `
    <section class="flow-section" data-section-panel="scopes-claims">
      ${sectionHead("Scopes & Claims", "Scopes are what the SP requested. Claims are what the IdP actually returned in the ID Token and UserInfo response.")}
      <div class="analysis-grid">
        <article class="flow-detail-panel">
          <header>
            <h3>Scopes demandés</h3>
          </header>
          ${scopesList(scopes)}
        </article>
        <article class="flow-detail-panel">
          <header>
            <h3>ID Token Analysis</h3>
          </header>
          ${idTokenState
            ? `<p class="muted">${escapeHtml(idTokenState)}</p>`
            : dl([
                row("Issuer", badge(analysisChecks.issuer)),
                row("Audience", badge(analysisChecks.audience)),
                row("Expiration", badge(analysisChecks.expiration)),
                row("Nonce", badge(analysisChecks.nonce)),
                row("Result", badge(analysisChecks.result))
              ])}
        </article>
        <article class="flow-detail-panel">
          <header>
            <h3>Claims reçus dans l'ID Token</h3>
            ${rawButton}
          </header>
          ${idTokenState
            ? `<p class="muted">${escapeHtml(idTokenState)}</p>`
            : claimTable(idTokenClaims, "No readable ID Token claims.")}
        </article>
        <article class="flow-detail-panel">
          <header>
            <h3>Claims reçus dans UserInfo</h3>
            ${userInfoRawButton}
          </header>
          ${userInfoState
            ? `<p class="muted">${escapeHtml(userInfoState)}</p>`
            : claimTable(userInfoClaims, "No readable UserInfo claims.")}
        </article>
      </div>
    </section>`;
}

// ---- Page ----

export function renderFlowDetailsPage({ flow, serviceProvider, steps = [], flash }) {
  const status = flow.statusBadge || { label: "Running", tone: "neutral" };
  const tabs = computeSectionTabs(steps);

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Flow Details",
      description: `${serviceProvider.name || flow.serviceProviderName || "Service Provider"} · ${status.label} · ${flow.id}`,
      actions: renderIconBtn({ icon: "return", label: "Back to result", href: `/oidc/flows/${encodeURIComponent(flow.id)}`, variant: "neutral", showLabel: true })
    })}

    <section class="card">
      <div class="card__body">
        <dl class="flow-meta">
          <div>
            <dt>Protocol</dt>
            <dd><span class="badge badge--neutral">OIDC</span></dd>
          </div>
          <div>
            <dt>Service Provider</dt>
            <dd>${escapeHtml(serviceProvider.name || flow.serviceProviderName || "Unknown")}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>${flow.environmentLabel
              ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>`
              : `<span class="badge badge--warning">Environment missing</span>`}</dd>
          </div>
          <div>
            <dt>Result</dt>
            <dd><span class="badge badge--${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span></dd>
          </div>
          <div>
            <dt>Flow ID</dt>
            <dd><code class="code-inline">${escapeHtml(flow.id)}</code></dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>${escapeHtml(formatDate(flow.startedAt))}</dd>
          </div>
          <div>
            <dt>Completed</dt>
            <dd>${escapeHtml(formatDate(flow.completedAt))}</dd>
          </div>
          <div>
            <dt>Duration</dt>
            <dd>${escapeHtml(formatDuration(flow.durationMs))}</dd>
          </div>
          <div>
            <dt>Failed step</dt>
            <dd>${flow.failedStep ? escapeHtml(flow.failedStep) : `<span class="muted">None</span>`}</dd>
          </div>
          <div>
            <dt>Final error</dt>
            <dd>${flow.errorDescription ? escapeHtml(flow.errorDescription) : `<span class="muted">None</span>`}</dd>
          </div>
        </dl>
      </div>
    </section>

    <div data-sections-layout>
      ${renderSectionNav(tabs)}
      ${renderAuthorization(steps)}
      ${renderTokenExchange(steps)}
      ${renderUserInfo(steps)}
      ${renderScopesAndClaims(flow, steps)}
    </div>

    <div class="modal-backdrop" data-raw-modal hidden>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="raw-modal-title">
        <header class="modal__header">
          <div>
            <h2 id="raw-modal-title">Sanitized raw data</h2>
            <p class="modal__subtitle muted" data-raw-modal-subtitle></p>
          </div>
        </header>
        <div class="modal__body">
          <pre class="raw-json-block" data-raw-modal-body>No raw data recorded for this step.</pre>
        </div>
        <footer class="modal__footer">
          ${renderIconBtn({ icon: "copy", label: "Copy", variant: "neutral", attr: "data-raw-copy" })}
          ${renderIconBtn({ icon: "return", label: "Close", variant: "neutral", attr: "data-raw-close" })}
        </footer>
      </section>
    </div>`;

  return renderLayout({
    title: "Flow details — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
