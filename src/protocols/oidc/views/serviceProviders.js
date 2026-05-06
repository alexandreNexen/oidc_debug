import { escapeHtml, renderFlash, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

function renderEmptyState() {
  return `
    <div class="card">
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No Service Provider configured yet.</p>
          <p class="empty-state__hint muted">Add a Service Provider to prepare an OIDC test against Ez-Access.</p>
          <a class="button-secondary button-compact" href="/service-providers/new">Add Service Provider</a>
        </div>
      </div>
    </div>
  `;
}

function renderScopes(scopes = "") {
  if (!scopes) {
    return `<span class="muted">Missing</span>`;
  }

  return scopes
    .split(" ")
    .filter(Boolean)
    .map((scope) => `<span class="scope-pill">${escapeHtml(scope)}</span>`)
    .join("");
}

function renderEnvironment(sp) {
  if (!sp.environment) {
    return `<span class="badge badge--warning">Environment missing</span>`;
  }

  return `<span class="badge badge--neutral">${escapeHtml(sp.environmentLabel || sp.environment)}</span>`;
}

function renderList(serviceProviders) {
  const rows = serviceProviders
    .map((sp) => {
      const secretLabel = sp.secretConfigured ? "Configured" : "Missing";
      const secretTone = sp.secretConfigured ? "success" : "warning";
      const status = sp.status || { label: "Missing", tone: "warning" };
      const lastFlow = sp.lastFlow;
      const lastFlowHtml = lastFlow
        ? `<a href="/flows/${encodeURIComponent(lastFlow.id)}"><span class="badge badge--${escapeHtml(lastFlow.statusBadge.tone)}">${escapeHtml(lastFlow.statusBadge.label)}</span></a>`
        : `<span class="muted">Not executed yet</span>`;

      return `
        <tr>
            <td>
            <div class="table__primary">${escapeHtml(sp.name || "Unnamed")}</div>
          </td>
          <td>${renderEnvironment(sp)}</td>
          <td><code class="code-inline">${escapeHtml(sp.clientId || "Missing client_id")}</code></td>
          <td><div class="scope-list">${renderScopes(sp.scopes)}</div></td>
          <td><span class="badge badge--${secretTone}">${escapeHtml(secretLabel)}</span></td>
          <td>${lastFlowHtml}</td>
          <td><span class="badge badge--${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span></td>
          <td class="table__actions">
            <form method="post" action="/flows/start/${encodeURIComponent(sp.id)}">
              <button type="submit" class="button">Run flow</button>
            </form>
            <a class="button-secondary" href="/service-providers/${encodeURIComponent(sp.id)}/edit">Edit</a>
            ${lastFlow ? `<a class="button-secondary" href="/flows/${encodeURIComponent(lastFlow.id)}/details">Details</a>` : ""}
            <form method="post" action="/service-providers/${encodeURIComponent(sp.id)}/delete" data-confirm="Delete this Service Provider?">
              <button type="submit" class="danger-button danger-button--compact">Delete</button>
            </form>
          </td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="card">
      <header class="card-header">
        <h2 class="card-header__title">All Service Providers</h2>
        <span class="muted">${escapeHtml(String(serviceProviders.length))} configured</span>
      </header>
      <div class="card__body card__body--flush table-scroll">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Environment</th>
              <th scope="col">Client ID</th>
              <th scope="col">Scopes</th>
              <th scope="col">Secret</th>
              <th scope="col">Last flow</th>
              <th scope="col">Status</th>
              <th scope="col" class="table__actions">Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

export function renderServiceProvidersPage({ serviceProviders = [], flash }) {
  const isEmpty = serviceProviders.length === 0;

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Service Providers",
      actions: `<a class="button button-compact" href="/service-providers/new">Add Service Provider</a>`
    })}
    ${isEmpty ? renderEmptyState() : renderList(serviceProviders)}
  `;

  return renderLayout({
    title: "Service Providers — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
