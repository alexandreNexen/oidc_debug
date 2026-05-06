import { escapeHtml, renderFlash, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

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

function resultTitle(status) {
  if (status === "success") {
    return "Flow completed successfully";
  }

  if (status === "failed") {
    return "Flow failed";
  }

  if (status === "partial_success") {
    return "Flow partially completed";
  }

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

function renderTimeline(steps = []) {
  return `
    <ol class="flow-timeline">
      ${steps
        .map(
          (step) => `
            <li class="flow-timeline__item flow-timeline__item--${escapeHtml(step.badge.tone)}">
              <span class="flow-timeline__dot"></span>
              <span class="flow-timeline__label">${escapeHtml(step.stepName)}</span>
              <span class="badge badge--${escapeHtml(step.badge.tone)}">${escapeHtml(step.badge.label)}</span>
            </li>
          `
        )
        .join("")}
    </ol>
  `;
}

export function renderFlowResultPage({ flow, serviceProvider, steps = [], flash, recommendedAction = "" }) {
  const status = flow.statusBadge || { label: "Running", tone: "neutral" };
  const failed = flow.status === "failed" || flow.status === "partial_success";
  const detailsHref = `/flows/${encodeURIComponent(flow.id)}/details`;

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
          ${failed && flow.failedStep ? renderSummaryRow("Failed step", `<span class="badge badge--warning">${escapeHtml(flow.failedStep)}</span>`) : ""}
          ${failed && flow.errorCode ? renderSummaryRow("Error code", `<code class="code-inline">${escapeHtml(flow.errorCode)}</code>`) : ""}
          ${failed && flow.errorDescription ? renderSummaryRow("Error", escapeHtml(flow.errorDescription)) : ""}
          ${failed && recommendedAction ? renderSummaryRow("Recommended action", escapeHtml(recommendedAction)) : ""}
        </dl>
      </div>
    </section>

    <section class="card flow-section">
      <header class="card-header">
        <h2 class="card-header__title">Completed steps</h2>
      </header>
      <div class="card__body">
        ${renderTimeline(steps)}
      </div>
    </section>

    <div class="flow-actions">
      <a class="button button-compact" href="${escapeHtml(detailsHref)}">View flow details</a>
      <form method="post" action="/flows/${encodeURIComponent(flow.id)}/rerun">
        <button type="submit" class="button-secondary button-compact">Run again</button>
      </form>
      ${failed && serviceProvider?.id ? `<a class="button-secondary button-compact" href="/service-providers/${encodeURIComponent(serviceProvider.id)}/edit">Edit Service Provider</a>` : ""}
      <a class="button-secondary button-compact" href="/service-providers">Back to Service Providers</a>
    </div>
  `;

  return renderLayout({
    title: "Flow result — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
