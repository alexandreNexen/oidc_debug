import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../../../common/views/layout.js";

function renderRedirectUriBlock(redirectUri) {
  if (!redirectUri) return "";
  return `
    <div class="redirect-uri-block">
      <span class="redirect-uri-block__label">Redirect URI</span>
      <code class="code-inline redirect-uri-block__uri">${escapeHtml(redirectUri)}</code>
      ${renderIconBtn({ icon: "copy", label: "Copy Redirect URI", variant: "neutral", attr: `data-copy="${escapeHtml(redirectUri)}" data-copy-label="Redirect URI"` })}
    </div>
  `;
}

function renderEmptyState() {
  return `
    <div class="card">
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No Service Provider configured yet.</p>
          <p class="empty-state__hint muted">Add a Service Provider to prepare an OIDC test against Ez-Access.</p>
          ${renderIconBtn({ icon: "add", label: "Add Service Provider", href: "/service-providers/new", variant: "success", showLabel: true })}
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
        ? `<a href="/flows/${encodeURIComponent(lastFlow.id)}">${renderStatusIcon(lastFlow.statusBadge)}</a>`
        : `<span class="muted">Not executed yet</span>`;

      return `
        <tr>
            <td>
            <div class="table__primary">${escapeHtml(sp.name || "Unnamed")}</div>
          </td>
          <td>${renderEnvironment(sp)}</td>
          <td><code class="code-inline">${escapeHtml(sp.clientId || "Missing client_id")}</code></td>
          <td><div class="scope-list">${renderScopes(sp.scopes)}</div></td>
          <td>${renderStatusIcon({ tone: secretTone, label: secretLabel })}</td>
          <td>${lastFlowHtml}</td>
          <td>${renderStatusIcon(status)}</td>
          <td class="table__actions">
            ${renderIconBtn({ icon: "start", label: "Run flow", href: `/flows/start/${encodeURIComponent(sp.id)}`, variant: "success" })}
            ${renderIconBtn({ icon: "edit", label: "Edit", href: `/service-providers/${encodeURIComponent(sp.id)}/edit`, variant: "neutral" })}
            ${lastFlow ? renderIconBtn({ icon: "details", label: "Details", href: `/flows/${encodeURIComponent(lastFlow.id)}/details`, variant: "neutral" }) : ""}
            <form method="post" action="/service-providers/${encodeURIComponent(sp.id)}/delete" data-confirm="Delete this Service Provider?">
              ${renderIconBtn({ icon: "delete", label: "Delete", type: "submit", variant: "danger" })}
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

export function renderServiceProvidersPage({ serviceProviders = [], flash, fixedRedirectUri = "" }) {
  const isEmpty = serviceProviders.length === 0;

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "OIDC Service Providers",
      actions: renderIconBtn({ icon: "add", label: "Add Service Provider", href: "/service-providers/new", variant: "success", showLabel: true })
    })}
    ${renderRedirectUriBlock(fixedRedirectUri)}
    ${isEmpty ? renderEmptyState() : renderList(serviceProviders)}
  `;

  return renderLayout({
    title: "OIDC Service Providers — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
