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

function getMetadataMode(values = {}) {
  if (values.idpMetadataMode === "xml" || values.idpMetadataMode === "url") {
    return values.idpMetadataMode;
  }
  if (values.idpMetadataUrl) {
    return "url";
  }
  if (values.idpMetadataXml) {
    return "xml";
  }
  return "url";
}

function renderIdpMetadataField({ values = {}, errors = {} }) {
  const mode = getMetadataMode(values);
  const urlSelected = mode === "url";
  const xmlSelected = mode === "xml";

  return `
    <fieldset class="sp-form__field metadata-field" data-metadata-mode>
      <legend class="sp-form__label">IdP Metadata <span class="muted">(optionnel)</span></legend>
      <div class="segmented-control" role="radiogroup" aria-label="IdP Metadata mode">
        <input class="segmented-control__input" type="radio" id="idp-metadata-mode-url" name="idpMetadataMode" value="url"${urlSelected ? " checked" : ""} data-metadata-mode-option>
        <label class="segmented-control__option" for="idp-metadata-mode-url">URL</label>
        <input class="segmented-control__input" type="radio" id="idp-metadata-mode-xml" name="idpMetadataMode" value="xml"${xmlSelected ? " checked" : ""} data-metadata-mode-option>
        <label class="segmented-control__option" for="idp-metadata-mode-xml">XML</label>
      </div>
      <div class="metadata-field__panel" data-metadata-panel="url"${urlSelected ? "" : " hidden"}>
        <input
          id="field-idpMetadataUrl"
          name="idpMetadataUrl"
          type="url"
          value="${escapeHtml(values.idpMetadataUrl || "")}"
          placeholder="https://idp.example.com/metadata"
          ${errors.idpMetadataUrl ? `aria-invalid="true" aria-describedby="field-idpMetadataUrl-error"` : ""}
          data-metadata-value
        />
        ${errors.idpMetadataUrl ? `<p id="field-idpMetadataUrl-error" class="field-error">${escapeHtml(errors.idpMetadataUrl)}</p>` : ""}
      </div>
      <div class="metadata-field__panel" data-metadata-panel="xml"${xmlSelected ? "" : " hidden"}>
        <textarea
          id="field-idpMetadataXml"
          name="idpMetadataXml"
          rows="6"
          placeholder="${escapeHtml("<?xml version=\"1.0\"?>\n<EntityDescriptor ...>")}"
          ${errors.idpMetadataXml ? `aria-invalid="true" aria-describedby="field-idpMetadataXml-error"` : ""}
          data-metadata-value
        >${escapeHtml(values.idpMetadataXml || "")}</textarea>
        ${errors.idpMetadataXml ? `<p id="field-idpMetadataXml-error" class="field-error">${escapeHtml(errors.idpMetadataXml)}</p>` : ""}
      </div>
    </fieldset>
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

export function renderSamlServiceProviderNewPage({ flash, form = {}, ezAccessEnvironments = [] } = {}) {
  const values = form.values || {};
  const errors = form.errors || {};
  const warnings = form.warnings || [];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      actions: renderIconBtn({ icon: "return", label: "Back to list", href: "/saml/service-providers", variant: "neutral", showLabel: true })
    })}

    <section class="card">
      <div class="card__body">
        ${renderErrorSummary(errors)}
        ${renderWarnings(warnings)}
        <form class="sp-form" method="post" action="/saml/service-providers" novalidate>

          ${renderField({ label: "Name", name: "name", value: values.name || "", error: errors.name, required: true })}
          ${renderEnvironmentField({ environments: ezAccessEnvironments, value: values.environment || "", error: errors.environment })}
          ${renderField({
            label: "SP Entity ID",
            name: "spEntityId",
            value: values.spEntityId || "",
            error: errors.spEntityId,
            required: true,
          })}
          ${renderIdpMetadataField({ values, errors })}

          <div class="sp-form__actions">
            ${renderIconBtn({ icon: "save", label: "Save SAML Service Provider", type: "submit", variant: "success", showLabel: true })}
            ${renderIconBtn({ icon: "return", label: "Cancel", href: "/saml/service-providers", variant: "neutral", showLabel: true })}
          </div>
        </form>
      </div>
    </section>
  `;

  return renderLayout({
    title: "Add SAML Service Provider — Ez-Access Debug",
    activeNav: "saml-service-providers",
    body
  });
}
