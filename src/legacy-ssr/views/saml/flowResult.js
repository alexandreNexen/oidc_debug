import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../common/layout.js";

function formatDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "Not available";
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "Running";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function resultTitle(status) {
  if (status === "success") return "Flow completed successfully";
  if (status === "failed") return "Flow failed";
  if (status === "partial_success") return "Flow partially completed";
  return "Flow running";
}

function renderSummaryRow(label, value) {
  return `
    <div class="kv-list__row">
      <dt>${escapeHtml(label)}</dt>
      <dd>${value}</dd>
    </div>
  `;
}

// ---- Functional section mapping ----

const STEP_TO_SECTION = {
  authn_request_created: "Authentication exchange",
  redirect_to_idp: "Authentication exchange",
  acs_callback_received: "Authentication exchange",
  saml_response_received: "Authentication exchange",
  saml_response_decoded: "Identity assertion"
};

function sectionBadge(status) {
  if (status === "success") return { tone: "success", label: "Done" };
  if (status === "error") return { tone: "error", label: "Error" };
  if (status === "running") return { tone: "warning", label: "Running" };
  if (status === "skipped") return { tone: "neutral", label: "Skipped" };
  return { tone: "neutral", label: "Pending" };
}

function computeSections(steps) {
  const byName = new Map(steps.map((s) => [s.stepName, s]));
  const authn = byName.get("authn_request_created");
  const redirect = byName.get("redirect_to_idp");
  const samlResp = byName.get("saml_response_received");
  const decoded = byName.get("saml_response_decoded");

  let exchangeStatus = "pending";
  if (authn?.status === "error" || redirect?.status === "error" || samlResp?.status === "error") {
    exchangeStatus = "error";
  } else if (samlResp?.status === "success") {
    exchangeStatus = "success";
  } else if (authn?.status === "success") {
    exchangeStatus = "running";
  }

  const identityStatus = decoded?.status || "pending";

  return [
    { label: "Authentication exchange", status: exchangeStatus },
    { label: "Identity assertion", status: identityStatus }
  ];
}

function renderFunctionalTimeline(steps) {
  const sections = computeSections(steps);
  return `
    <ol class="flow-timeline">
      ${sections.map((s) => {
        const badge = sectionBadge(s.status);
        return `
          <li class="flow-timeline__item flow-timeline__item--${escapeHtml(badge.tone)}">
            <span class="flow-timeline__dot"></span>
            <span class="flow-timeline__label">${escapeHtml(s.label)}</span>
            ${renderStatusIcon(badge)}
          </li>
        `;
      }).join("")}
    </ol>
  `;
}

export function renderSamlFlowResultPage({ flow, serviceProvider, steps = [], flash }) {
  const status = flow.statusBadge || { label: "Running", tone: "neutral" };
  const failed = flow.status === "failed" || flow.status === "partial_success";
  const detailsHref = `/legacy/saml/flows/${encodeURIComponent(flow.id)}/details`;
  const failedSectionLabel = flow.failedStep ? (STEP_TO_SECTION[flow.failedStep] || flow.failedStep) : "";

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Flow result",
      description: resultTitle(flow.status),
      actions: `<span class="badge badge--${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span>`
    })}

    <section class="card">
      <header class="card-header">
        <h2 class="card-header__title">Summary</h2>
      </header>
      <div class="card__body">
        <dl class="kv-list">
          ${renderSummaryRow("Service Provider", escapeHtml(serviceProvider.name || "Unknown"))}
          ${renderSummaryRow("Environment", flow.environmentLabel
            ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>`
            : `<span class="badge badge--warning">Environment missing</span>`
          )}
          ${renderSummaryRow("SP Entity ID", `<code class="code-inline">${escapeHtml(flow.runtime?.spEntityId || "")}</code>`)}
          ${renderSummaryRow("IdP SSO URL", flow.runtime?.ssoUrl
            ? `<code class="code-inline">${escapeHtml(flow.runtime.ssoUrl)}</code>`
            : `<span class="muted">Not available</span>`
          )}
          ${renderSummaryRow("IdP Entity ID", flow.runtime?.idpEntityId
            ? `<code class="code-inline">${escapeHtml(flow.runtime.idpEntityId)}</code>`
            : `<span class="muted">Not available</span>`
          )}
          ${renderSummaryRow("ACS URL", `<code class="code-inline">${escapeHtml(flow.runtime?.acsUrl || "")}</code>`)}
          ${renderSummaryRow("RelayState", flow.runtime?.relayStatePresent || flow.runtime?.relayStateSha25612
            ? "Present"
            : `<span class="muted">Absent</span>`
          )}
          ${renderSummaryRow("Started at", escapeHtml(formatDate(flow.startedAt)))}
          ${renderSummaryRow("Duration", escapeHtml(formatDuration(flow.durationMs)))}
          ${failed && failedSectionLabel ? renderSummaryRow("Failed at", `<span class="badge badge--warning">${escapeHtml(failedSectionLabel)}</span>`) : ""}
          ${failed && flow.errorCode ? renderSummaryRow("Error code", `<code class="code-inline">${escapeHtml(flow.errorCode)}</code>`) : ""}
          ${failed && flow.errorDescription ? renderSummaryRow("Error", escapeHtml(flow.errorDescription)) : ""}
        </dl>
      </div>
    </section>

    <section class="card flow-section">
      <header class="card-header">
        <h2 class="card-header__title">Steps</h2>
      </header>
      <div class="card__body">
        ${renderFunctionalTimeline(steps)}
      </div>
    </section>

    <div class="flow-actions">
      ${renderIconBtn({ icon: "details", label: "View flow details", href: detailsHref, variant: "neutral", showLabel: true })}
      ${renderIconBtn({ icon: "replay", label: "Run again", href: `/saml/flows/start/${encodeURIComponent(flow.serviceProviderId)}`, variant: "neutral", showLabel: true })}
      ${failed && serviceProvider?.id
        ? renderIconBtn({ icon: "edit", label: "Edit Service Provider", href: `/legacy/saml/service-providers/${encodeURIComponent(serviceProvider.id)}/edit`, variant: "neutral", showLabel: true })
        : ""}
      ${renderIconBtn({ icon: "return", label: "Back to list", href: "/legacy/saml/service-providers", variant: "neutral", showLabel: true })}
    </div>
  `;

  return renderLayout({
    title: "Flow result — Ez-Access SAML Debug",
    activeNav: "saml-service-providers",
    body
  });
}
