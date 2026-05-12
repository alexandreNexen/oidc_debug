import { escapeHtml, renderFlash, renderLayout, renderStatusIcon } from "./layout.js";

function renderRecentFlowsCard(recentFlows = [], samlRecentFlows = []) {
  const allFlows = [...recentFlows, ...samlRecentFlows]
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, 5);

  if (allFlows.length) {
    const rows = allFlows
      .map(
        (flow) => {
          const href = flow.href || `/oidc/flows/${encodeURIComponent(flow.id)}`;
          const title = flow.serviceProviderName || flow.clientId || flow.id;
          const startedAt = new Date(flow.startedAt).toLocaleString("fr-FR");
          const protocol = flow.protocol || "OIDC";

          return `
          <li class="dashboard-flow-list__item">
            <a class="dashboard-flow-list__link" href="${escapeHtml(href)}" aria-label="Open ${escapeHtml(protocol)} flow ${escapeHtml(title)} started at ${escapeHtml(startedAt)}">
              <span class="dashboard-flow-list__content">
                <span class="dashboard-flow-list__title">${escapeHtml(title)}</span>
                <span class="muted">${escapeHtml(startedAt)}</span>
              </span>
              <span class="dashboard-flow-list__meta">
                <span class="badge badge--neutral dashboard-flow-list__protocol">${escapeHtml(protocol)}</span>
                ${renderStatusIcon(flow.statusBadge)}
              </span>
            </a>
          </li>
        `;
        }
      )
      .join("");

    return `
      <section class="card" aria-labelledby="flows-card-title">
        <header class="card-header">
          <h2 id="flows-card-title" class="card-header__title">Recent flows</h2>
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

export function renderDashboard({ recentFlows = [], samlRecentFlows = [], flash }) {
  const body = `
    ${renderFlash(flash)}
    <div class="dashboard">
      ${renderRecentFlowsCard(recentFlows, samlRecentFlows)}
    </div>
  `;

  return renderLayout({
    title: "Ez-Access Debug Console",
    activeNav: "dashboard",
    body
  });
}
