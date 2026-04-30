import { escapeHtml, renderFlash, renderLayout, renderPageHeader } from "./layout.js";

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

export function renderServiceProviderNewPage({ flash, form = {}, ezAccessEnvironments = [] } = {}) {
  const values = form.values || {};
  const errors = form.errors || {};
  const warnings = form.warnings || [];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Add Service Provider",
      description: "Create an OIDC client configuration for a future Ez-Access test flow.",
      actions: `<a class="button-secondary button-compact" href="/service-providers">Back to list</a>`
    })}

    <section class="card">
      <header class="card-header">
        <h2 class="card-header__title">Service Provider details</h2>
        <span class="badge badge--neutral">New</span>
      </header>
      <div class="card__body">
        ${renderErrorSummary(errors)}
        ${renderWarnings(warnings)}
        <form class="sp-form" method="post" action="/service-providers" novalidate>
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
            help: "Stored encrypted and never shown again in clear text.",
            error: errors.client_secret,
            required: true
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
            <button type="submit" class="button button-compact">Save Service Provider</button>
            <a class="button-secondary button-compact" href="/service-providers">Cancel</a>
          </div>
        </form>
      </div>
    </section>
  `;

  return renderLayout({
    title: "Add Service Provider — Ez-Access OIDC Debug",
    activeNav: "service-providers",
    body
  });
}
