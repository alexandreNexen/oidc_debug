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

const BADGE_SUCCESS = new Set(["yes", "received", "present", "sent", "valid", "success", "match", "ok"]);
const BADGE_ERROR = new Set(["no", "missing", "failed", "mismatch", "error", "failure"]);
const BADGE_NEUTRAL = new Set(["not implemented", "not checked", "not extracted", "skipped", "none",
  "disabled", "not sent", "pending", "not performed", "not available"]);

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

function code(v) {
  if (!v) return `<span class="muted">—</span>`;
  return `<code class="code-inline">${escapeHtml(String(v))}</code>`;
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

  const diag = token?.responseData?.id_token_diagnostics;
  const idTokenStatus = diag?.id_token_received === "yes" ? "success"
    : (token && token.status !== "pending") ? "pending"
    : "pending";

  return [
    { id: "authorization", label: "Authorization", num: 1, status: authStatus },
    { id: "token-exchange", label: "Token exchange", num: 2, status: tokenStatus },
    { id: "userinfo", label: "UserInfo", num: 3, status: uiStatus },
    { id: "id-token", label: "ID Token analysis", num: 4, status: idTokenStatus }
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
        row("Authorization endpoint", code(rd.endpoint)),
        row("Client ID", plain(rd.client_id)),
        row("Redirect URI", plain(rd.redirect_uri)),
        row("Scopes", plain(rd.scope)),
        row("Response type", plain(rd.response_type || "code")),
        row("PKCE", badge(rd.pkce)),
        row("State", badge(rd.state)),
        row("Nonce", badge(rd.nonce)),
        row("Browser redirect", badge(rd.http_mode ? "prepared" : ""))
      ]);

  const responseContent = !cb
    ? `<p class="muted">${authPending ? "Not started." : "Waiting for callback…"}</p>`
    : dl([
        row("Callback received", badge("yes")),
        row("Authorization code", badge(cbrd.authorization_code)),
        row("State", badge(cbrd.state)),
        row("State validation", badge(cbrd.state_validation)),
        row("Provider error", cbrd.error ? `<span class="badge badge--error">${escapeHtml(cbrd.error)}</span>` : badge("none")),
        cbrd.error_description ? row("Error description", plain(cbrd.error_description)) : null
      ]);

  return `
    <section class="flow-section" data-section-panel="authorization">
      ${sectionHead("Authorization", "The SP prepares an authorization request to the IdP. The IdP redirects the user back to the callback with an authorization code.")}
      <div class="exchange-grid">
        ${exchangePanel("Request",
          rawBtn("Raw Authorization Request", "authorize", "request", auth?.rawRequestData),
          requestContent,
          auth?.errorData?.errorDescription)}
        ${exchangePanel("Response",
          rawBtn("Raw Callback Response", "callback", "response", cb?.rawResponseData),
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
        row("Token endpoint", code(rd.endpoint)),
        row("Grant type", plain(rd.grant_type)),
        row("Authorization code", badge(rd.authorization_code)),
        row("Redirect URI", plain(rd.redirect_uri)),
        row("Client authentication", plain(rd.client_authentication_method)),
        row("Client secret", badge(rd.client_secret_used)),
        row("Code verifier", badge(rd.code_verifier))
      ]);

  const tokenError = resp.token_error && resp.token_error !== "none";
  const responseContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : dl([
        row("HTTP status", badge(resp.http_status != null ? String(resp.http_status) : "")),
        row("Access token", badge(resp.access_token)),
        row("ID token", badge(resp.id_token)),
        row("Refresh token", badge(resp.refresh_token)),
        resp.token_type ? row("Token type", plain(resp.token_type)) : null,
        resp.expires_in != null && resp.expires_in !== "" ? row("Expires in", plain(`${resp.expires_in} s`)) : null,
        row("Token error", tokenError
          ? `<span class="badge badge--error">${escapeHtml(String(resp.token_error))}</span>`
          : badge("none")),
        tokenError && resp.error_description ? row("Error description", plain(resp.error_description)) : null
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

  const requestContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : dl([
        row("UserInfo endpoint", code(rd.endpoint)),
        row("Method", plain(rd.method || "GET")),
        row("Access token", badge("used / masked")),
        row("Authorization header", badge("Bearer present"))
      ]);

  const uiError = resp.error && resp.error !== "none";
  const responseContent = notReached
    ? `<p class="muted">Not reached.</p>`
    : skipped
    ? `<p class="muted">Skipped — ${escapeHtml(resp.skipped_reason || "no reason provided")}.</p>`
    : dl([
        row("HTTP status", badge(resp.http_status != null ? String(resp.http_status) : "")),
        row("Subject", resp.subject ? plain(resp.subject) : badge("missing")),
        row("Email", badge(resp.email_present === "yes" ? "present" : "missing")),
        row("Name", badge(resp.name_present === "yes" ? "present" : "missing")),
        row("Claims available", badge(resp.raw_claims_available)),
        row("Error", uiError
          ? `<span class="badge badge--error">${escapeHtml(String(resp.error))}</span>`
          : badge("none")),
        uiError && resp.error_description ? row("Error description", plain(resp.error_description)) : null
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

// ---- Section 4: ID Token analysis ----

function renderIdTokenAnalysis(steps) {
  const token = steps.find((s) => s.stepName === "token");
  const diag = token?.responseData?.id_token_diagnostics;
  const rawButton = rawBtn("Raw Token Response", "token", "response", token?.rawResponseData);
  const noData = !diag || diag.id_token_received === "no";

  return `
    <section class="flow-section" data-section-panel="id-token">
      ${sectionHead("ID Token analysis", "The SP inspects the identity token received to understand the identity information and available validations.")}
      <article class="flow-detail-panel">
        <header>
          <h3>ID Token</h3>
          ${rawButton}
        </header>
        ${noData
          ? `<p class="muted">${token ? "No ID token received." : "Not reached."}</p>`
          : dl([
              row("ID token received", badge(diag.id_token_received)),
              diag.format ? row("Format", plain(diag.format)) : null,
              diag.decode_error ? row("Decode error", plain(diag.decode_error)) : null,
              diag.jwt_header_alg ? row("Algorithm (alg)", plain(diag.jwt_header_alg)) : null,
              diag.jwt_header_kid ? row("Key ID (kid)", plain(diag.jwt_header_kid)) : null,
              diag.issuer ? row("Issuer", plain(diag.issuer)) : null,
              diag.audience ? row("Audience", plain(diag.audience)) : null,
              diag.subject ? row("Subject", plain(diag.subject)) : null,
              diag.expiration ? row("Expiration", plain(diag.expiration)) : null,
              diag.issued_at ? row("Issued at", plain(diag.issued_at)) : null,
              row("Nonce claim present", badge(diag.nonce_claim_present)),
              row("Nonce validation", badge(diag.nonce_validation)),
              row("Signature validation", badge(diag.signature_validation || "not implemented"))
            ])}
      </article>
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
      ${renderIdTokenAnalysis(steps)}
    </div>

    <div class="modal-backdrop" data-raw-modal hidden>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="raw-modal-title">
        <header class="modal__header">
          <div>
            <h2 id="raw-modal-title">Raw data</h2>
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
