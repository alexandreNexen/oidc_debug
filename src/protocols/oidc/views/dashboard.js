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


const startButtons = `
  <div style="display:flex;gap:.5rem">
    ${renderIconBtn({ icon: "start", label: "OIDC flow", href: "/service-providers", variant: "success", showLabel: true })}
    ${renderIconBtn({ icon: "start", label: "SAML flow", href: "/saml/service-providers", variant: "success", showLabel: true })}
  </div>
`;

function renderRecentFlowsCard(recentFlows = [], samlRecentFlows = []) {
  const allFlows = [...recentFlows, ...samlRecentFlows]
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, 5);

  if (allFlows.length) {
    const rows = allFlows
      .map(
        (flow) => `
          <li class="dashboard-flow-list__item">
            <div>
              <a class="text-action" href="${escapeHtml(flow.href || `/flows/${encodeURIComponent(flow.id)}`)}">${escapeHtml(flow.serviceProviderName || flow.clientId || flow.id)}</a>
              <span class="muted">${escapeHtml(new Date(flow.startedAt).toLocaleString("fr-FR"))}</span>
            </div>
            <div style="display:flex;align-items:center;gap:.5rem">
              <span class="badge badge--neutral" style="font-size:.7rem">${escapeHtml(flow.protocol || "OIDC")}</span>
              ${renderStatusIcon(flow.statusBadge)}
            </div>
          </li>
        `
      )
      .join("");

    return `
      <section class="card" aria-labelledby="flows-card-title">
        <header class="card-header">
          <h2 id="flows-card-title" class="card-header__title">Recent flows</h2>
          ${startButtons}
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
        ${startButtons}
      </header>
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No flow executed yet.</p>
          <p class="empty-state__hint muted">Run an OIDC or SAML flow to see history here.</p>
        </div>
      </div>
    </section>
  `;
}

export function renderDashboard({ recentFlows = [], samlRecentFlows = [], ezAccessEnvironments = [], flash }) {
  const body = `
    ${renderFlash(flash)}
    <div class="dashboard">
      ${renderEzAccessCard(ezAccessEnvironments)}
      ${renderRecentFlowsCard(recentFlows, samlRecentFlows)}
    </div>
  `;

  return renderLayout({
    title: "Ez-Access OIDC Debug Console",
    activeNav: "dashboard",
    body
  });
}
