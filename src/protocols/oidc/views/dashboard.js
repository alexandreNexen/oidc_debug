import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderStatusIcon } from "../../../common/views/layout.js";

function renderEnvironmentStatus(environment) {
  const configured = Boolean(environment.discoveryConfigured);

  return `
    <div class="environment-status">
      <span>${escapeHtml(environment.shortLabel || environment.label)}</span>
      ${configured
        ? renderStatusIcon({ tone: "success", label: "Discovery URL configured" })
        : `<span class="badge badge--warning">Discovery URL missing</span>`}
    </div>
  `;
}

function renderEzAccessCard(environments = []) {
  return `
    <section class="card" aria-labelledby="ez-access-card-title">
      <header class="card-header">
        <h2 id="ez-access-card-title" class="card-header__title">Ez-Access Environments</h2>
      </header>
      <div class="card__body">
        <div class="environment-status-list">
          ${environments.map(renderEnvironmentStatus).join("")}
        </div>
      </div>
    </section>
  `;
}


function renderRecentFlowsCard(recentFlows = []) {
  if (recentFlows.length) {
    const rows = recentFlows
          .map(
        (flow) => `
          <li class="dashboard-flow-list__item">
            <div>
              <a class="text-action" href="/flows/${encodeURIComponent(flow.id)}">${escapeHtml(flow.serviceProviderName || flow.clientId || flow.id)}</a>
              <span class="muted">${escapeHtml(new Date(flow.startedAt).toLocaleString("en-US"))}</span>
            </div>
            ${renderStatusIcon(flow.statusBadge)}
          </li>
        `
      )
      .join("");

    return `
      <section class="card" aria-labelledby="flows-card-title">
        <header class="card-header">
          <h2 id="flows-card-title" class="card-header__title">Recent flows</h2>
          ${renderIconBtn({ icon: "start", label: "Start a flow", href: "/service-providers", variant: "success" })}
        </header>
        <div class="card__body">
          <ul class="dashboard-flow-list">${rows}</ul>
        </div>
      </section>
    `;
  }

  return `
    <section class="card" aria-labelledby="flows-card-title">
        <header class="card-header">
          <h2 id="flows-card-title" class="card-header__title">Recent flows</h2>
          <span class="muted">Recent OIDC test history</span>
        </header>
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No flow executed yet.</p>
          <p class="empty-state__hint muted">Flow history will be available after implementing persisted flows.</p>
        </div>
      </div>
    </section>
  `;
}

export function renderDashboard({ recentFlows = [], ezAccessEnvironments = [], flash }) {
  const body = `
    ${renderFlash(flash)}
    <div class="dashboard">
      ${renderEzAccessCard(ezAccessEnvironments)}
      ${renderRecentFlowsCard(recentFlows)}
    </div>
  `;

  return renderLayout({
    title: "Ez-Access OIDC Debug Console",
    activeNav: "dashboard",
    body
  });
}
