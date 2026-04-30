import { escapeHtml, renderFlash, renderLayout, renderPageHeader } from "./layout.js";

const EXCHANGE_LABELS = {
  authorize: "GET /authorize",
  callback: "GET /oidc/callback",
  token: "POST /token",
  userinfo: "GET /userinfo"
};

const STEP_LABELS = {
  authorize: "Authorize",
  callback: "Callback",
  token: "Token",
  userinfo: "UserInfo"
};

function formatDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "Not available";
}

function formatDuration(durationMs) {
  if (durationMs === null || durationMs === undefined) {
    return "Running";
  }

  if (durationMs < 1000) {
    return `${durationMs} ms`;
  }

  return `${(durationMs / 1000).toFixed(1)} s`;
}

function renderDataValue(key, value) {
  if (value === null || value === undefined || value === "") {
    return `<span class="muted">Not available</span>`;
  }

  if (key === "authorization_url_full") {
    return `
      <details class="inline-details">
        <summary>Show authorization URL</summary>
        <code class="code-block">${escapeHtml(value)}</code>
      </details>
    `;
  }

  if (typeof value === "object") {
    return `
      <details class="inline-details" open>
        <summary>View data</summary>
        <pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>
      </details>
    `;
  }

  return `<span>${escapeHtml(value)}</span>`;
}

function renderDataList(data = {}) {
  if (!data || Object.keys(data).length === 0) {
    return `<p class="muted">No data recorded.</p>`;
  }

  return `
    <dl class="flow-data-list">
      ${Object.entries(data)
        .map(
          ([key, value]) => `
            <div class="flow-data-list__row">
              <dt>${escapeHtml(key)}</dt>
              <dd>${renderDataValue(key, value)}</dd>
            </div>
          `
        )
        .join("")}
    </dl>
  `;
}

function encodeRawData(value) {
  if (!value || (typeof value === "object" && Object.keys(value).length === 0)) {
    return "";
  }

  return Buffer.from(JSON.stringify(value, null, 2), "utf8").toString("base64");
}

function renderRawButton(step, type, rawData) {
  const label = type === "request" ? "Request" : "Response";
  const title = `Raw ${STEP_LABELS[step.stepName] || step.stepName} ${label}`;

  return `
    <button
      class="panel-action-button"
      type="button"
      data-raw-open
      data-raw-title="${escapeHtml(title)}"
      data-raw-step="${escapeHtml(step.stepName)}"
      data-raw-type="${escapeHtml(label)}"
      data-raw-json="${escapeHtml(encodeRawData(rawData))}"
    >Raw</button>
  `;
}

function renderTimeline(flow, steps, selectedStep) {
  return `
    <nav class="flow-detail-timeline" aria-label="Flow steps">
      ${steps
        .map(
          (step, index) => `
            <a class="flow-detail-timeline__item text-action${step.stepName === selectedStep ? " is-active" : ""}" href="/flows/${encodeURIComponent(flow.id)}/details?step=${encodeURIComponent(step.stepName)}">
              <span>${escapeHtml(step.stepName)}</span>
              <span class="badge badge--${escapeHtml(step.badge.tone)}">${escapeHtml(step.badge.label)}</span>
            </a>
            ${index < steps.length - 1 ? `<span class="flow-detail-timeline__separator">→</span>` : ""}
          `
        )
        .join("")}
    </nav>
  `;
}

function renderSelectedStep(step) {
  const exchange = EXCHANGE_LABELS[step.stepName] || step.stepName;

  return `
    <section class="flow-detail-grid" aria-label="${escapeHtml(step.stepName)} details">
      <article class="flow-detail-panel">
        <header>
          <div>
            <h2>Request</h2>
            <span class="muted">Ce qu'on envoie</span>
          </div>
          ${renderRawButton(step, "request", step.rawRequestData)}
        </header>
        ${renderDataList(step.requestData)}
      </article>

      <article class="flow-detail-panel flow-detail-panel--center">
        <header>
          <h2>OIDC Exchange</h2>
        </header>
        <dl class="flow-data-list">
          <div class="flow-data-list__row">
            <dt>Exchange</dt>
            <dd>${escapeHtml(exchange)}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Method</dt>
            <dd>${escapeHtml(step.httpMethod || "Not available")}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Endpoint</dt>
            <dd>${step.endpoint ? `<code class="code-inline">${escapeHtml(step.endpoint)}</code>` : `<span class="muted">Not available</span>`}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>HTTP status</dt>
            <dd>${step.httpStatus !== null && step.httpStatus !== undefined ? escapeHtml(String(step.httpStatus)) : `<span class="muted">Not available</span>`}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Status</dt>
            <dd><span class="badge badge--${escapeHtml(step.badge.tone)}">${escapeHtml(step.badge.label)}</span></dd>
          </div>
        </dl>
        ${step.errorData ? `<div class="form-banner form-banner--error">${renderDataList(step.errorData)}</div>` : ""}
      </article>

      <article class="flow-detail-panel">
        <header>
          <div>
            <h2>Response</h2>
            <span class="muted">Ce qu'on reçoit</span>
          </div>
          ${renderRawButton(step, "response", step.rawResponseData)}
        </header>
        ${renderDataList(step.responseData)}
      </article>
    </section>
  `;
}

export function renderFlowDetailsPage({ flow, serviceProvider, steps = [], selectedStep, flash }) {
  const status = flow.statusBadge || { label: "Running", tone: "neutral" };
  const step = steps.find((entry) => entry.stepName === selectedStep) || steps[0];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Flow Details",
      description: `${serviceProvider.name || flow.serviceProviderName || "Service Provider"} · ${status.label} · ${flow.id}`,
      actions: `<a class="button-secondary button-compact" href="/flows/${encodeURIComponent(flow.id)}">Back to result</a>`
    })}

    <section class="card">
      <div class="card__body">
        <dl class="flow-meta">
          <div>
            <dt>Service Provider</dt>
            <dd>${escapeHtml(serviceProvider.name || flow.serviceProviderName || "Unknown")}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>${flow.environmentLabel ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>` : `<span class="badge badge--warning">Environment missing</span>`}</dd>
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
            <dt>Duration</dt>
            <dd>${escapeHtml(formatDuration(flow.durationMs))}</dd>
          </div>
          <div>
            <dt>Failed step</dt>
            <dd>${flow.failedStep ? escapeHtml(flow.failedStep) : `<span class="muted">None</span>`}</dd>
          </div>
        </dl>
      </div>
    </section>

    ${renderTimeline(flow, steps, selectedStep)}
    ${renderSelectedStep(step)}
    <div class="modal-backdrop" data-raw-modal hidden>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="raw-modal-title">
        <header class="modal__header">
          <div>
            <h2 id="raw-modal-title">Raw data</h2>
            <p class="modal__subtitle muted" data-raw-modal-subtitle></p>
          </div>
          <button class="panel-action-button button-compact" type="button" data-raw-close>Close</button>
        </header>
        <div class="modal__body">
          <pre class="raw-json-block" data-raw-modal-body>No raw data recorded for this step.</pre>
        </div>
        <footer class="modal__footer">
          <button class="button-secondary button-compact" type="button" data-raw-copy>Copy</button>
          <button class="button button-compact" type="button" data-raw-close>Close</button>
        </footer>
      </section>
    </div>
  `;

  return renderLayout({
    title: "Flow details — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
