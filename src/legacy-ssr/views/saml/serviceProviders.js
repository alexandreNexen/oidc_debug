import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../common/layout.js";

function renderEnvironment(sp) {
  if (!sp.environment) {
    return `<span class="badge badge--warning">Missing</span>`;
  }
  return `<span class="badge badge--neutral">${escapeHtml(sp.environmentLabel || sp.environment)}</span>`;
}

function renderIdpMetadata(sp) {
  if (sp.idpMetadataUrl) {
    return `<span class="badge badge--success">URL</span>`;
  }
  if (sp.idpMetadataXml) {
    return `<span class="badge badge--success">XML</span>`;
  }
  return `<span class="badge badge--warning">Missing</span>`;
}

function formatLastFlowDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "Unknown date";
}

function renderLastFlow(lastFlow) {
  if (!lastFlow) {
    return `<span class="muted">Not executed yet</span>`;
  }

  const startedAt = formatLastFlowDate(lastFlow.startedAt);
  const label = lastFlow.statusBadge?.label || lastFlow.status || "Flow";

  return `
    <a class="last-flow-link" href="/legacy/saml/flows/${encodeURIComponent(lastFlow.id)}" aria-label="Open last SAML flow, ${escapeHtml(label)}, started at ${escapeHtml(startedAt)}">
      ${renderStatusIcon(lastFlow.statusBadge)}
      <span class="last-flow-link__text">
        <span class="last-flow-link__date muted">${escapeHtml(startedAt)}</span>
      </span>
    </a>
  `;
}

function renderEmptyState() {
  return `
    <div class="card">
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No SAML Service Provider configured yet.</p>
          <p class="empty-state__hint muted">Add a Service Provider to configure a SAML connection to Ez-Access.</p>
          ${renderIconBtn({ icon: "add", href: "/legacy/saml/service-providers/new", variant: "success", showLabel: true })}
        </div>
      </div>
    </div>
  `;
}

function renderList(serviceProviders) {
  const rows = serviceProviders
    .map((sp) => {
      const status = sp.status || { label: "Incomplete", tone: "warning" };
      return `
        <tr>
          <td><div class="table__primary">${escapeHtml(sp.name || "Unnamed")}</div></td>
          <td>${renderEnvironment(sp)}</td>
          <td><code class="code-inline">${escapeHtml(sp.spEntityId || "Missing")}</code></td>
          <td>${renderIdpMetadata(sp)}</td>
          <td>${renderLastFlow(sp.lastFlow)}</td>
          <td>${renderStatusIcon(status)}</td>
          <td class="table__actions">
            ${renderIconBtn({ icon: "start", label: "Run SAML Flow", href: `/saml/flows/start/${encodeURIComponent(sp.id)}`, variant: "success" })}
            ${renderIconBtn({ icon: "edit", label: "Edit", href: `/legacy/saml/service-providers/${encodeURIComponent(sp.id)}/edit`, variant: "neutral" })}
            <form method="post" action="/legacy/saml/service-providers/${encodeURIComponent(sp.id)}/delete" data-confirm="Delete this SAML Service Provider?">
              ${renderIconBtn({ icon: "delete", label: "Delete", type: "submit", variant: "danger" })}
            </form>
          </td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="card">
      <div class="card__body card__body--flush table-scroll">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Environment</th>
              <th scope="col">SP Entity ID</th>
              <th scope="col">IdP Metadata</th>
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

export function renderSamlServiceProvidersPage({ serviceProviders = [], flash }) {
  const isEmpty = serviceProviders.length === 0;

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "SAML Service Providers",
      actions: renderIconBtn({ icon: "add", href: "/legacy/saml/service-providers/new", variant: "success", showLabel: true })
    })}
    ${isEmpty ? renderEmptyState() : renderList(serviceProviders)}
  `;

  return renderLayout({
    title: "SAML Service Providers — Ez-Access Debug",
    activeNav: "saml-service-providers",
    body
  });
}
