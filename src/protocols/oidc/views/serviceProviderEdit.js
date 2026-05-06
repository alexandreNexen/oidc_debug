import { escapeHtml, renderFlash, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

function renderField({ label, name, type = "text", value = "", placeholder = "", help = "", error = "", required = false }) {
  const fieldId = `field-${name}`;
  const errorId = `${fieldId}-error`;

  return `
    <div class="sp-form__field">
      <label class="sp-form__label" for="${escapeHtml(fieldId)}">${escapeHtml(label)}</label>
      <input
        id="${escapeHtml(fieldId)}"
        name="${escapeHtml(name)}"
        type="${escapeHtml(type)}"
        value="${type === "password" ? "" : escapeHtml(value)}"
        placeholder="${escapeHtml(placeholder)}"
        ${required ? "required" : ""}
        ${error ? `aria-invalid="true" aria-describedby="${escapeHtml(errorId)}"` : ""}
      />
      ${error ? `<p id="${escapeHtml(errorId)}" class="field-error">${escapeHtml(error)}</p>` : ""}
    </div>
  `;
}

function renderEnvironmentField({ environments = [], value = "", error = "" }) {
  const fieldId = "field-environment";
  const errorId = `${fieldId}-error`;

  return `
    <div class="sp-form__field">
      <label class="sp-form__label" for="${fieldId}">Environment</label>
      <select
        id="${fieldId}"
        name="environment"
        required
        ${error ? `aria-invalid="true" aria-describedby="${escapeHtml(errorId)}"` : ""}
      >
        <option value="">Select Ez-Access environment</option>
        ${environments
          .map(
            (environment) =>
              `<option value="${escapeHtml(environment.key)}"${environment.key === value ? " selected" : ""}>${escapeHtml(environment.label)}</option>`
          )
          .join("")}
      </select>
      ${error ? `<p id="${escapeHtml(errorId)}" class="field-error">${escapeHtml(error)}</p>` : ""}
    </div>
  `;
}

function renderWarnings(warnings = []) {
  if (!warnings.length) {
    return "";
  }

  return `<div class="form-banner form-banner--warning">${warnings.map((warning) => escapeHtml(warning)).join("<br />")}</div>`;
}

function renderErrorSummary(errors = {}) {
  const messages = Object.values(errors).filter(Boolean);
  if (!messages.length) {
    return "";
  }

  return `<div class="form-banner form-banner--error">Please fix the highlighted fields.</div>`;
}

export function renderServiceProviderEditPage({ serviceProvider, flash, form = {}, ezAccessEnvironments = [] } = {}) {
  const values = {
    name: serviceProvider?.name || "",
    environment: serviceProvider?.environment || "",
    clientId: serviceProvider?.clientId || "",
    scopes: serviceProvider?.scopes || "",
    ...(form.values || {})
  };
  const errors = form.errors || {};
  const warnings = form.warnings || [];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Edit Service Provider",
      description: "Update the OIDC client metadata used by future test flows.",
      actions: `<a class="button-secondary button-compact" href="/service-providers">Back to list</a>`
    })}

    <section class="card">
      <header class="card-header">
        <div class="card-header__main">
          <h2 class="card-header__title">${escapeHtml(serviceProvider?.name || "Service Provider")}</h2>
          <span class="muted code-inline">${escapeHtml(serviceProvider?.clientId || "client_id missing")}</span>
        </div>
        <span class="badge badge--${escapeHtml(serviceProvider?.status?.tone || "neutral")}">${escapeHtml(serviceProvider?.status?.label || "Missing")}</span>
      </header>
      <div class="card__body">
        ${renderErrorSummary(errors)}
        ${renderWarnings(warnings)}
        <form class="sp-form" method="post" action="/service-providers/${encodeURIComponent(serviceProvider.id)}" novalidate>
          ${renderField({
            label: "Name",
            name: "name",
            value: values.name,
            error: errors.name,
            required: true
          })}
          ${renderEnvironmentField({
            environments: ezAccessEnvironments,
            value: values.environment,
            error: errors.environment
          })}
          ${renderField({
            label: "Client ID",
            name: "client_id",
            value: values.clientId,
            error: errors.client_id,
            required: true
          })}
          ${renderField({
            label: "Client Secret",
            name: "client_secret",
            type: "password",
            placeholder: "Leave blank to keep existing secret",
            help: "Leave blank to keep existing secret.",
            error: errors.client_secret
          })}
          ${renderField({
            label: "Scopes",
            name: "scopes",
            value: values.scopes,
            placeholder: "openid",
            help: "Required scope: openid",
            error: errors.scopes,
            required: true
          })}

          <div class="sp-form__actions">
            <button type="submit" class="button button-compact">Save changes</button>
            <a class="button-secondary button-compact" href="/service-providers">Cancel</a>
          </div>
        </form>

        <form class="sp-form__delete" method="post" action="/service-providers/${encodeURIComponent(serviceProvider.id)}/delete" data-confirm="Delete this Service Provider?">
          <button type="submit" class="danger-button">Delete</button>
        </form>
      </div>
    </section>
  `;

  return renderLayout({
    title: "Edit Service Provider — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
