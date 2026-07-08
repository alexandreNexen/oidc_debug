import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../../../common/views/layout.js";

function formatDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "Not available";
}

function formatDuration(durationMs) {
  if (durationMs === null || durationMs === undefined) return "Running";
  if (durationMs < 1000) return `${durationMs} ms`;
  return `${(durationMs / 1000).toFixed(1)} s`;
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
  authorize: "Authorization",
  callback: "Authorization",
  token: "Token exchange",
  introspection: "Introspection",
  userinfo: "UserInfo"
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
  const auth = byName.get("authorize");
  const cb = byName.get("callback");
  const token = byName.get("token");
  const ui = byName.get("userinfo");

  let authStatus = "pending";
  if (auth?.status === "error" || cb?.status === "error") authStatus = "error";
  else if (cb?.status === "success") authStatus = "success";
  else if (auth?.status === "success") authStatus = "running";

  const tokenStatus = token?.status || "pending";

  let uiStatus = ui?.status || "pending";
  if (uiStatus === "pending" && tokenStatus === "success") uiStatus = "pending";

  let idTokenStatus = "pending";
  if (token?.status === "error") {
    idTokenStatus = "error";
  } else if (token?.status === "success") {
    idTokenStatus = "success";
  }

  return [
    { label: "Authorization", status: authStatus },
    { label: "Token exchange", status: tokenStatus },
    { label: "UserInfo", status: uiStatus },
    { label: "ID Token analysis", status: idTokenStatus }
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

export function renderFlowResultPage({ flow, serviceProvider, steps = [], flash, recommendedAction = "" }) {
  const status = flow.statusBadge || { label: "Running", tone: "neutral" };
  const failed = flow.status === "failed" || flow.status === "partial_success";
  const detailsHref = `/oidc/flows/${encodeURIComponent(flow.id)}/details`;
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
          ${renderSummaryRow("Service Provider", escapeHtml(serviceProvider.name || flow.serviceProviderName || "Unknown"))}
          ${renderSummaryRow("Environment", flow.environmentLabel ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>` : `<span class="badge badge--warning">Environment missing</span>`)}
          ${renderSummaryRow("Client ID", `<code class="code-inline">${escapeHtml(serviceProvider.clientId || flow.clientId || "")}</code>`)}
          ${renderSummaryRow("Started at", escapeHtml(formatDate(flow.startedAt)))}
          ${renderSummaryRow("Duration", escapeHtml(formatDuration(flow.durationMs)))}
          ${failed && failedSectionLabel ? renderSummaryRow("Failed at", `<span class="badge badge--warning">${escapeHtml(failedSectionLabel)}</span>`) : ""}
          ${failed && flow.errorCode ? renderSummaryRow("Error code", `<code class="code-inline">${escapeHtml(flow.errorCode)}</code>`) : ""}
          ${failed && flow.errorDescription ? renderSummaryRow("Error", escapeHtml(flow.errorDescription)) : ""}
          ${failed && recommendedAction ? renderSummaryRow("Recommended action", escapeHtml(recommendedAction)) : ""}
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
      <form method="post" action="/oidc/flows/${encodeURIComponent(flow.id)}/rerun">
        ${renderIconBtn({ icon: "replay", label: "Run again", type: "submit", variant: "neutral", showLabel: true })}
      </form>
      ${failed && serviceProvider?.id ? renderIconBtn({ icon: "edit", label: "Edit Service Provider", href: `/oidc/service-providers/${encodeURIComponent(serviceProvider.id)}/edit`, variant: "neutral", showLabel: true }) : ""}
      ${renderIconBtn({ icon: "return", label: "Back to Service Providers", href: "/oidc/service-providers", variant: "neutral", showLabel: true })}
    </div>
  `;

  return renderLayout({
    title: "Flow result — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
