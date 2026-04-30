import { escapeHtml, renderFlash, renderLayout } from "./layout.js";

function renderEnvironmentStatus(environment) {
  const configured = Boolean(environment.discoveryConfigured);

  return `
    <div class="environment-status">
      <span>${escapeHtml(environment.shortLabel || environment.label)}</span>
      <span class="badge badge--${configured ? "success" : "warning"}">${configured ? "Discovery URL configured" : "Discovery URL missing"}</span>
    </div>
  `;
}

function renderEzAccessCard(environments = [], redirectUri) {
  return `
    <section class="card" aria-labelledby="ez-access-card-title">
      <header class="card-header">
        <h2 id="ez-access-card-title" class="card-header__title">Ez-Access Environments</h2>
      </header>
      <div class="card__body">
        <div class="environment-status-list">
          ${environments.map(renderEnvironmentStatus).join("")}
        </div>
        <dl class="kv-list">
          <div class="kv-list__row">
            <dt>Redirect URI</dt>
            <dd class="kv-list__redirect">
              <code class="code-inline">${escapeHtml(redirectUri)}</code>
              <button type="button" class="copy-button button-compact" data-copy="${escapeHtml(redirectUri)}" data-copy-label="Redirect URI">Copy Redirect URI</button>
            </dd>
          </div>
        </dl>
      </div>
    </section>
  `;
}

function renderServiceProvidersCard(serviceProviders) {
  const isEmpty = serviceProviders.length === 0;
  const addHref = "/service-providers/new";
  const manageHref = "/service-providers";
  const preview = serviceProviders
    .slice(0, 3)
          .map(
      (sp) => `
        <li class="dashboard-sp-list__item">
          <span>${escapeHtml(sp.name || sp.clientId || "Unnamed")}</span>
          <code class="code-inline">${escapeHtml(sp.clientId || "Missing client_id")}</code>
        </li>
      `
    )
    .join("");

  const populatedBody = `
    <div class="dashboard-sp-summary">
      <p class="muted">${escapeHtml(String(serviceProviders.length))} Service Provider(s) registered.</p>
      <a class="text-action" href="${escapeHtml(manageHref)}">View all Service Providers</a>
    </div>
    <ul class="dashboard-sp-list">${preview}</ul>
  `;

  const emptyBody = `
    <div class="empty-state">
      <p class="empty-state__title">No Service Provider configured yet.</p>
      <p class="empty-state__hint muted">Add a Service Provider to prepare an OIDC test against Ez-Access.</p>
      <a class="button-secondary button-compact" href="${escapeHtml(addHref)}">Add Service Provider</a>
    </div>
  `;

  return `
    <section class="card" aria-labelledby="sp-card-title">
      <header class="card-header">
        <h2 id="sp-card-title" class="card-header__title">Service Providers</h2>
        <a class="button button-compact" href="${escapeHtml(addHref)}">Add Service Provider</a>
      </header>
      <div class="card__body${isEmpty ? " card__body--centered" : ""}">
        ${isEmpty ? emptyBody : populatedBody}
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
            <span class="badge badge--${escapeHtml(flow.statusBadge.tone)}">${escapeHtml(flow.statusBadge.label)}</span>
          </li>
        `
      )
      .join("");

    return `
      <section class="card" aria-labelledby="flows-card-title">
        <header class="card-header">
          <h2 id="flows-card-title" class="card-header__title">Recent flows</h2>
          <a class="text-action" href="/service-providers">Start a flow</a>
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

export function renderDashboard({ providerConfig, serviceProviders = [], recentFlows = [], ezAccessEnvironments = [], fixedRedirectUri, flash }) {
  const redirectUri = fixedRedirectUri || providerConfig?.redirectUri || "";

  const body = `
    ${renderFlash(flash)}
    <div class="dashboard">
      ${renderEzAccessCard(ezAccessEnvironments, redirectUri)}
      ${renderServiceProvidersCard(serviceProviders)}
      ${renderRecentFlowsCard(recentFlows)}
    </div>
  `;

  return renderLayout({
    title: "Ez-Access OIDC Debug Console",
    activeNav: "dashboard",
    body
  });
}
