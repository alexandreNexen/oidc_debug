import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

function renderField({ label, name, type = "text", value = "", placeholder = "", error = "", required = false, hint = "" }) {
  const fieldId = `field-${name}`;
  const errorId = `${fieldId}-error`;
  return `
    <div class="sp-form__field">
      <label class="sp-form__label" for="${escapeHtml(fieldId)}">${escapeHtml(label)}${required ? "" : ` <span class="muted">(optionnel)</span>`}</label>
      <input
        id="${escapeHtml(fieldId)}"
        name="${escapeHtml(name)}"
        type="${escapeHtml(type)}"
        value="${escapeHtml(value)}"
        placeholder="${escapeHtml(placeholder)}"
        ${required ? "required" : ""}
        ${error ? `aria-invalid="true" aria-describedby="${escapeHtml(errorId)}"` : ""}
      />
      ${hint ? `<p class="muted" style="font-size:.85em;margin:.2rem 0 0">${escapeHtml(hint)}</p>` : ""}
      ${error ? `<p id="${escapeHtml(errorId)}" class="field-error">${escapeHtml(error)}</p>` : ""}
    </div>
  `;
}

function renderTextareaField({ label, name, value = "", placeholder = "", error = "", required = false, hint = "", rows = 4 }) {
  const fieldId = `field-${name}`;
  const errorId = `${fieldId}-error`;
  return `
    <div class="sp-form__field">
      <label class="sp-form__label" for="${escapeHtml(fieldId)}">${escapeHtml(label)}${required ? "" : ` <span class="muted">(optionnel)</span>`}</label>
      <textarea
        id="${escapeHtml(fieldId)}"
        name="${escapeHtml(name)}"
        rows="${rows}"
        placeholder="${escapeHtml(placeholder)}"
        ${required ? "required" : ""}
        ${error ? `aria-invalid="true" aria-describedby="${escapeHtml(errorId)}"` : ""}
        style="font-family:monospace;font-size:.875rem;resize:vertical"
      >${escapeHtml(value)}</textarea>
      ${hint ? `<p class="muted" style="font-size:.85em;margin:.2rem 0 0">${escapeHtml(hint)}</p>` : ""}
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
      <select id="${fieldId}" name="environment" required ${error ? `aria-invalid="true" aria-describedby="${escapeHtml(errorId)}"` : ""}>
        <option value="">Select Ez-Access environment</option>
        ${environments.map((env) => `<option value="${escapeHtml(env.key)}"${env.key === value ? " selected" : ""}>${escapeHtml(env.label)}</option>`).join("")}
      </select>
      ${error ? `<p id="${escapeHtml(errorId)}" class="field-error">${escapeHtml(error)}</p>` : ""}
    </div>
  `;
}

function renderWarnings(warnings = []) {
  if (!warnings.length) return "";
  return `<div class="form-banner form-banner--warning">${warnings.map((w) => escapeHtml(w)).join("<br />")}</div>`;
}

function renderErrorSummary(errors = {}) {
  if (!Object.values(errors).filter(Boolean).length) return "";
  return `<div class="form-banner form-banner--error">Please fix the highlighted fields.</div>`;
}

function renderAcsUrlBanner(acsUrl) {
  return `
    <div class="redirect-uri-block" style="margin-bottom:1.25rem">
      <span class="redirect-uri-block__label">ACS URL</span>
      <code class="code-inline redirect-uri-block__uri">${escapeHtml(acsUrl)}</code>
      ${renderIconBtn({ icon: "copy", label: "Copy ACS URL", variant: "neutral", attr: `data-copy="${escapeHtml(acsUrl)}"` })}
    </div>
  `;
}

export function renderSamlServiceProviderEditPage({ serviceProvider, flash, form = {}, ezAccessEnvironments = [], acsUrl = "" } = {}) {
  const sp = serviceProvider || {};
  const values = {
    name: sp.name || "",
    environment: sp.environment || "",
    spEntityId: sp.spEntityId || "",
    idpMetadataUrl: sp.idpMetadataUrl || "",
    idpMetadataXml: sp.idpMetadataXml || "",
    ...(form.values || {})
  };
  const errors = form.errors || {};
  const warnings = form.warnings || [];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Edit SAML Service Provider",
      actions: renderIconBtn({ icon: "return", label: "Back to list", href: "/saml/service-providers", variant: "neutral", showLabel: true })
    })}

    <section class="card">
      <div class="card__body">
        ${acsUrl ? renderAcsUrlBanner(acsUrl) : ""}
        ${renderErrorSummary(errors)}
        ${renderWarnings(warnings)}
        <form class="sp-form" method="post" action="/saml/service-providers/${encodeURIComponent(sp.id)}" novalidate>

          ${renderField({ label: "Name", name: "name", value: values.name, error: errors.name, required: true })}
          ${renderEnvironmentField({ environments: ezAccessEnvironments, value: values.environment, error: errors.environment })}
          ${renderField({
            label: "SP Entity ID",
            name: "spEntityId",
            value: values.spEntityId,
            error: errors.spEntityId,
            required: true,
          })}
          ${renderField({
            label: "IdP Metadata URL",
            name: "idpMetadataUrl",
            value: values.idpMetadataUrl,
            error: errors.idpMetadataUrl,
            placeholder: "https://idp.example.com/metadata",
          })}
          ${renderTextareaField({
            label: "IdP Metadata XML",
            name: "idpMetadataXml",
            value: values.idpMetadataXml,
            error: errors.idpMetadataXml,
            placeholder: "<?xml version=\"1.0\"?>\n<EntityDescriptor ...>",
            rows: 6,
          })}

          <div class="sp-form__actions">
            ${renderIconBtn({ icon: "save", label: "Save changes", type: "submit", variant: "success" })}
            ${renderIconBtn({ icon: "return", label: "Cancel", href: "/saml/service-providers", variant: "neutral", showLabel: true })}
          </div>
        </form>

        <div class="sp-form__delete" style="display:flex;gap:.75rem">
          <form method="post" action="/saml/service-providers/${encodeURIComponent(sp.id)}/delete" data-confirm="Delete this SAML Service Provider?">
            ${renderIconBtn({ icon: "delete", label: "Delete", type: "submit", variant: "danger", showLabel: true })}
          </form>
        </div>
      </div>
    </section>
  `;

  return renderLayout({
    title: "Edit SAML Service Provider — Ez-Access Debug",
    activeNav: "saml-service-providers",
    body
  });
}
