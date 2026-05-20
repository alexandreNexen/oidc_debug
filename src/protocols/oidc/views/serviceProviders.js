import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../../../common/views/layout.js";

function renderEmptyState() {
  return `
    <div class="card">
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No Service Provider configured yet.</p>
          <p class="empty-state__hint muted">Add a Service Provider to prepare an OIDC test against Ez-Access.</p>
          ${renderIconBtn({ icon: "add", href: "/oidc/service-providers/new", variant: "success", showLabel: true })}
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
    <a class="last-flow-link" href="/oidc/flows/${encodeURIComponent(lastFlow.id)}" aria-label="Open last OIDC flow, ${escapeHtml(label)}, started at ${escapeHtml(startedAt)}">
      ${renderStatusIcon(lastFlow.statusBadge)}
      <span class="last-flow-link__text">
        <span class="last-flow-link__date muted">${escapeHtml(startedAt)}</span>
      </span>
    </a>
  `;
}

function renderEndpointRow(label, value, fieldKey) {
  const content = value
    ? `<code class="code-inline">${escapeHtml(value)}</code>`
    : `<span class="muted">—</span>`;
  return `
    <div class="flow-data-list__row">
      <dt>${escapeHtml(label)}</dt>
      <dd data-field="${escapeHtml(fieldKey)}">${content}</dd>
    </div>
  `;
}

function renderGeneralPanel(redirectUri) {
  const copyBtn = redirectUri
    ? renderIconBtn({
        icon: "copy",
        label: "Copy Redirect URI",
        variant: "neutral",
        attr: `data-copy="${escapeHtml(redirectUri)}" data-copy-label="Redirect URI"`
      })
    : "";

  return `
    <details class="config-panel">
      <summary class="config-panel__summary">General</summary>
      <div class="config-panel__body">
        <div class="redirect-uri-block">
          <span class="redirect-uri-block__label">Redirect URI</span>
          <code class="code-inline redirect-uri-block__uri">${redirectUri ? escapeHtml(redirectUri) : "Not configured"}</code>
          ${copyBtn}
        </div>
        <dl class="flow-data-list">
          <div class="flow-data-list__row">
            <dt>PKCE enabled</dt>
            <dd>yes</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>PKCE method</dt>
            <dd>S256</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Response type</dt>
            <dd>code</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>Grant type</dt>
            <dd>authorization_code</dd>
          </div>
          <div class="flow-data-list__row">
            <dt>UserInfo enabled</dt>
            <dd>yes</dd>
          </div>
        </dl>
      </div>
    </details>
  `;
}

function renderCapabilitiesSection(env) {
  const caps = [
    { field: "scopesSupported", label: "Supported scopes", values: env.scopesSupported },
    { field: "responseTypesSupported", label: "Supported response types", values: env.responseTypesSupported },
    { field: "tokenEndpointAuthMethodsSupported", label: "Supported token auth methods", values: env.tokenEndpointAuthMethodsSupported }
  ];

  const rows = caps
    .map((cap) => {
      const isPresent = Array.isArray(cap.values) && cap.values.length > 0;
      return `
      <div class="flow-data-list__row" data-cap-row="${escapeHtml(cap.field)}"${isPresent ? "" : " hidden"}>
        <dt>${escapeHtml(cap.label)}</dt>
        <dd><span data-field="${escapeHtml(cap.field)}">${isPresent ? escapeHtml(cap.values.join(", ")) : ""}</span></dd>
      </div>
    `;
    })
    .join("");

  const hasCapabilities = caps.some((cap) => Array.isArray(cap.values) && cap.values.length > 0);

  return `
    <dl class="flow-data-list oidc-overview__caps" data-cap-container${hasCapabilities ? "" : " hidden"}>
      ${rows}
    </dl>
  `;
}

function renderEnvironmentPanel(env) {
  const envKey = env.key;
  const discoveryUrl = env.discoveryUrl || "";

  return `
    <details class="config-panel">
      <summary class="config-panel__summary">${escapeHtml(env.label || env.key)}</summary>
      <div class="config-panel__body">
        <form class="discovery-url-form" data-discovery-form data-env="${escapeHtml(envKey)}" action="/oidc/discovery/import/${escapeHtml(envKey)}" method="post">
          <div class="discovery-url-row">
            <label class="discovery-url-row__label" for="discovery-url-${escapeHtml(envKey)}">Discovery URL</label>
            <input
              type="url"
              id="discovery-url-${escapeHtml(envKey)}"
              name="discoveryUrl"
              class="discovery-url-row__input"
              value="${escapeHtml(discoveryUrl)}"
              placeholder="https://idp.example.com/.well-known/openid-configuration"
              data-discovery-url-input
            />
            <button type="submit" class="btn-icon btn-icon--labeled btn-icon--neutral" data-discovery-submit>
              <img src="/assets/icons/replay.svg" width="16" height="16" alt="" aria-hidden="true">
              Validate &amp; import
            </button>
          </div>
          <p class="discovery-url-row__error" data-discovery-error hidden></p>
        </form>
        <div data-discovery-endpoints="${escapeHtml(envKey)}">
          <dl class="flow-data-list">
            ${renderEndpointRow("Issuer", env.issuer, "issuer")}
            ${renderEndpointRow("Authorization endpoint", env.authorizationEndpoint, "authorizationEndpoint")}
            ${renderEndpointRow("Token endpoint", env.tokenEndpoint, "tokenEndpoint")}
            ${renderEndpointRow("UserInfo endpoint", env.userInfoEndpoint, "userInfoEndpoint")}
            ${renderEndpointRow("JWKS URI", env.jwksUri, "jwksUri")}
          </dl>
          ${renderCapabilitiesSection(env)}
        </div>
      </div>
    </details>
  `;
}

function renderOidcConfig(configuration = {}, fallbackRedirectUri = "") {
  const redirectUri = configuration.redirectUri || fallbackRedirectUri;
  const environments = Array.isArray(configuration.environments) ? configuration.environments : [];

  return `
    <section class="card oidc-overview">
      <header class="card-header">
        <h2 class="card-header__title">Configuration</h2>
      </header>
      <div class="card__body config-panels">
        ${renderGeneralPanel(redirectUri)}
        ${environments.map(renderEnvironmentPanel).join("")}
      </div>
    </section>
  `;
}

function renderList(serviceProviders) {
  const rows = serviceProviders
    .map((sp) => {
      const secretLabel = sp.secretConfigured ? "Configured" : "Missing";
      const secretTone = sp.secretConfigured ? "success" : "warning";
      const status = sp.status || { label: "Missing", tone: "warning" };
      const lastFlow = sp.lastFlow;

      return `
        <tr>
          <td>
            <div class="table__primary">${escapeHtml(sp.name || "Unnamed")}</div>
          </td>
          <td>${renderEnvironment(sp)}</td>
          <td><code class="code-inline">${escapeHtml(sp.clientId || "Missing client_id")}</code></td>
          <td><div class="scope-list">${renderScopes(sp.scopes)}</div></td>
          <td>${renderStatusIcon({ tone: secretTone, label: secretLabel })}</td>
          <td>${renderLastFlow(lastFlow)}</td>
          <td>${renderStatusIcon(status)}</td>
          <td class="table__actions">
            ${renderIconBtn({ icon: "start", label: "Run flow", href: `/oidc/flows/start/${encodeURIComponent(sp.id)}`, variant: "success" })}
            ${renderIconBtn({ icon: "edit", label: "Edit", href: `/oidc/service-providers/${encodeURIComponent(sp.id)}/edit`, variant: "neutral" })}
            <form method="post" action="/oidc/service-providers/${encodeURIComponent(sp.id)}/delete" data-confirm="Delete this Service Provider?">
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

export function renderServiceProvidersPage({ serviceProviders = [], flash, fixedRedirectUri = "", oidcPageConfiguration = {} }) {
  const isEmpty = serviceProviders.length === 0;

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "OIDC Service Providers",
      actions: renderIconBtn({ icon: "add", href: "/oidc/service-providers/new", variant: "success", showLabel: true })
    })}
    ${isEmpty ? renderEmptyState() : renderList(serviceProviders)}
    ${renderOidcConfig(oidcPageConfiguration, fixedRedirectUri)}
  `;

  return renderLayout({
    title: "OIDC Service Providers — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
