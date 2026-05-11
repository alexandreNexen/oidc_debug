import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../../../common/views/layout.js";

const STEP_LABELS = {
  authn_request_created: "AuthnRequest",
  redirect_to_idp: "Redirect IdP",
  acs_callback_received: "ACS Callback",
  saml_response_received: "SAMLResponse",
  saml_response_decoded: "Décodage"
};

const SAML_STEP_ORDER = [
  "authn_request_created",
  "redirect_to_idp",
  "acs_callback_received",
  "saml_response_received",
  "saml_response_decoded"
];

function formatDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "Non disponible";
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "En cours";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function renderDataValue(key, value) {
  if (value === null || value === undefined || value === "") {
    return `<span class="muted">Non disponible</span>`;
  }

  if (typeof value === "object") {
    return `
      <details class="inline-details" open>
        <summary>Voir les données</summary>
        <pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>
      </details>
    `;
  }

  return `<span>${escapeHtml(String(value))}</span>`;
}

function renderDataList(data = {}) {
  if (!data || Object.keys(data).length === 0) {
    return `<p class="muted">Aucune donnée enregistrée.</p>`;
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
  if (!value || (typeof value === "object" && Object.keys(value).length === 0)) return "";
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
    <nav class="flow-detail-timeline" aria-label="Étapes du flow SAML">
      ${steps
        .map(
          (step, index) => `
            <a class="flow-detail-timeline__item text-action${step.stepName === selectedStep ? " is-active" : ""}" href="/saml/flows/${encodeURIComponent(flow.id)}/details?step=${encodeURIComponent(step.stepName)}">
              <span>${escapeHtml(STEP_LABELS[step.stepName] || step.stepName)}</span>
              ${renderStatusIcon(step.badge)}
            </a>
            ${index < steps.length - 1 ? `<span class="flow-detail-timeline__separator">→</span>` : ""}
          `
        )
        .join("")}
    </nav>
  `;
}

function renderSelectedStep(step) {
  const label = STEP_LABELS[step.stepName] || step.stepName;

  return `
    <section class="flow-detail-grid" aria-label="${escapeHtml(label)} — détails">
      <article class="flow-detail-panel">
        <header>
          <div>
            <h2>Requête</h2>
            <span class="muted">Ce qu'on envoie</span>
          </div>
          ${step.rawRequestData ? renderRawButton(step, "request", step.rawRequestData) : ""}
        </header>
        ${renderDataList(step.requestData)}
      </article>

      <article class="flow-detail-panel flow-detail-panel--center">
        <header>
          <h2>Échange SAML</h2>
        </header>
        <dl class="flow-data-list">
          <div class="flow-data-list__row">
            <dt>Étape</dt>
            <dd>${escapeHtml(label)}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Méthode</dt>
            <dd>${escapeHtml(step.httpMethod || "Non disponible")}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Endpoint</dt>
            <dd>${step.endpoint ? `<code class="code-inline">${escapeHtml(step.endpoint)}</code>` : `<span class="muted">Non disponible</span>`}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>HTTP status</dt>
            <dd>${step.httpStatus !== null && step.httpStatus !== undefined ? escapeHtml(String(step.httpStatus)) : `<span class="muted">Non disponible</span>`}</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Statut</dt>
            <dd>${renderStatusIcon(step.badge)}</dd>
          </div>
        </dl>
        ${step.errorData ? `<div class="form-banner form-banner--error">${renderDataList(step.errorData)}</div>` : ""}
      </article>

      <article class="flow-detail-panel">
        <header>
          <div>
            <h2>Réponse</h2>
            <span class="muted">Ce qu'on reçoit</span>
          </div>
          ${step.rawResponseData ? renderRawButton(step, "response", step.rawResponseData) : ""}
        </header>
        ${renderDataList(step.responseData)}
      </article>
    </section>
  `;
}

export function renderSamlFlowDetailsPage({ flow, serviceProvider, steps = [], selectedStep, flash }) {
  const status = flow.statusBadge || { label: "En cours", tone: "neutral" };
  const step = steps.find((s) => s.stepName === selectedStep) || steps[0];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Détails du flow SAML",
      description: `${serviceProvider.name || "Service Provider"} · ${status.label} · ${flow.id}`,
      actions: renderIconBtn({ icon: "return", label: "Retour au résultat", href: `/saml/flows/${encodeURIComponent(flow.id)}`, variant: "neutral", showLabel: true })
    })}

    <section class="card">
      <div class="card__body">
        <dl class="flow-meta">
          <div>
            <dt>Service Provider</dt>
            <dd>${escapeHtml(serviceProvider.name || "Inconnu")}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>${flow.environmentLabel
              ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>`
              : `<span class="badge badge--warning">Environment manquant</span>`}</dd>
          </div>
          <div>
            <dt>SP Entity ID</dt>
            <dd><code class="code-inline">${escapeHtml(flow.runtime?.spEntityId || "")}</code></dd>
          </div>
          <div>
            <dt>Résultat</dt>
            <dd><span class="badge badge--${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span></dd>
          </div>
          <div>
            <dt>Flow ID</dt>
            <dd><code class="code-inline">${escapeHtml(flow.id)}</code></dd>
          </div>
          <div>
            <dt>Démarré</dt>
            <dd>${escapeHtml(formatDate(flow.startedAt))}</dd>
          </div>
          <div>
            <dt>Durée</dt>
            <dd>${escapeHtml(formatDuration(flow.durationMs))}</dd>
          </div>
          <div>
            <dt>Étape en échec</dt>
            <dd>${flow.failedStep ? escapeHtml(flow.failedStep) : `<span class="muted">Aucune</span>`}</dd>
          </div>
        </dl>
      </div>
    </section>

    ${step ? renderTimeline(flow, steps, selectedStep) : ""}
    ${step ? renderSelectedStep(step) : `<p class="muted">Aucune étape enregistrée.</p>`}

    <div class="modal-backdrop" data-raw-modal hidden>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="raw-modal-title">
        <header class="modal__header">
          <div>
            <h2 id="raw-modal-title">Données brutes</h2>
            <p class="modal__subtitle muted" data-raw-modal-subtitle></p>
          </div>
        </header>
        <div class="modal__body">
          <pre class="raw-json-block" data-raw-modal-body>Aucune donnée brute enregistrée pour cette étape.</pre>
        </div>
        <footer class="modal__footer">
          ${renderIconBtn({ icon: "copy", label: "Copier", variant: "neutral", attr: "data-raw-copy" })}
          ${renderIconBtn({ icon: "return", label: "Fermer", variant: "neutral", attr: "data-raw-close" })}
        </footer>
      </section>
    </div>
  `;

  return renderLayout({
    title: "Détails flow SAML — Ez-Access Debug",
    activeNav: "saml-service-providers",
    body
  });
}

export { SAML_STEP_ORDER };
