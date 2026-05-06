import { escapeHtml, renderFlash, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

const NAME_ID_FORMAT_OPTIONS = [
  { value: "", label: "Not specified" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", label: "Unspecified (SAML 1.1)" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", label: "Email Address (SAML 1.1)" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", label: "Persistent (SAML 2.0)" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", label: "Transient (SAML 2.0)" }
];

function renderField({ label, name, type = "text", value = "", placeholder = "", error = "", required = false, hint = "" }) {
  const fieldId = `field-${name}`;
  const errorId = `${fieldId}-error`;
  return `
    <div class="sp-form__field">
      <label class="sp-form__label" for="${escapeHtml(fieldId)}">${escapeHtml(label)}${required ? "" : " <span class=\"muted\">(optionnel)</span>"}</label>
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
      <label class="sp-form__label" for="${escapeHtml(fieldId)}">${escapeHtml(label)}${required ? "" : " <span class=\"muted\">(optionnel)</span>"}</label>
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

function renderCheckboxField({ label, name, checked = false, hint = "" }) {
  return `
    <div class="sp-form__field" style="flex-direction:row;align-items:center;gap:.5rem">
      <input
        id="field-${escapeHtml(name)}"
        name="${escapeHtml(name)}"
        type="checkbox"
        value="on"
        ${checked ? "checked" : ""}
        style="width:1rem;height:1rem;flex-shrink:0"
      />
      <label class="sp-form__label" for="field-${escapeHtml(name)}" style="margin:0">${escapeHtml(label)}</label>
      ${hint ? `<span class="muted" style="font-size:.85em">${escapeHtml(hint)}</span>` : ""}
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

function renderNameIdFormatField({ value = "", error = "" }) {
  const fieldId = "field-nameIdFormat";
  const errorId = `${fieldId}-error`;
  return `
    <div class="sp-form__field">
      <label class="sp-form__label" for="${fieldId}">NameID Format <span class="muted">(optionnel)</span></label>
      <select id="${fieldId}" name="nameIdFormat" ${error ? `aria-invalid="true" aria-describedby="${escapeHtml(errorId)}"` : ""}>
        ${NAME_ID_FORMAT_OPTIONS.map((opt) => `<option value="${escapeHtml(opt.value)}"${opt.value === value ? " selected" : ""}>${escapeHtml(opt.label)}</option>`).join("")}
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

export function renderSamlServiceProviderEditPage({ serviceProvider, flash, form = {}, ezAccessEnvironments = [] } = {}) {
  const sp = serviceProvider || {};
  const values = {
    name: sp.name || "",
    environment: sp.environment || "",
    idpMetadataUrl: sp.idpMetadataUrl || "",
    idpMetadataXml: sp.idpMetadataXml || "",
    spEntityId: sp.spEntityId || "",
    debugAcsUrl: sp.debugAcsUrl || "",
    nameIdFormat: sp.nameIdFormat || "",
    requestSigned: sp.requestSigned || false,
    wantResponseSigned: sp.wantResponseSigned || false,
    wantAssertionSigned: sp.wantAssertionSigned || false,
    requiredAttributes: sp.requiredAttributes || "",
    accessControlNotes: sp.accessControlNotes || "",
    logoutUrl: sp.logoutUrl || "",
    ...(form.values || {})
  };
  const errors = form.errors || {};
  const warnings = form.warnings || [];

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Edit SAML Service Provider",
      description: "Update the SAML configuration for this Service Provider.",
      actions: `<a class="button-secondary button-compact" href="/saml/service-providers">Back to list</a>`
    })}

    <section class="card">
      <header class="card-header">
        <div class="card-header__main">
          <h2 class="card-header__title">${escapeHtml(sp.name || "SAML Service Provider")}</h2>
          <span class="muted code-inline">${escapeHtml(sp.spEntityId || "entity ID missing")}</span>
        </div>
        <span class="badge badge--${escapeHtml(sp.status?.tone || "neutral")}">${escapeHtml(sp.status?.label || "Incomplete")}</span>
      </header>
      <div class="card__body">
        ${renderErrorSummary(errors)}
        ${renderWarnings(warnings)}
        <form class="sp-form" method="post" action="/saml/service-providers/${encodeURIComponent(sp.id)}" novalidate>

          ${renderField({ label: "Name", name: "name", value: values.name, error: errors.name, required: true })}
          ${renderEnvironmentField({ environments: ezAccessEnvironments, value: values.environment, error: errors.environment })}
          ${renderField({ label: "SP Entity ID", name: "spEntityId", value: values.spEntityId, error: errors.spEntityId, required: true, placeholder: "https://your-app.example.com/saml/metadata", hint: "Unique identifier for this Service Provider in SAML metadata." })}
          ${renderField({ label: "Debug ACS URL", name: "debugAcsUrl", value: values.debugAcsUrl, error: errors.debugAcsUrl, hint: "Assertion Consumer Service URL used for SAML tests." })}

          <hr style="border:none;border-top:1px solid var(--color-border,#e5e7eb);margin:1.5rem 0" />
          <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem">IdP Configuration</h3>

          ${renderField({ label: "IdP Metadata URL", name: "idpMetadataUrl", value: values.idpMetadataUrl, error: errors.idpMetadataUrl, placeholder: "https://idp.example.com/metadata" })}
          ${renderTextareaField({ label: "IdP Metadata XML", name: "idpMetadataXml", value: values.idpMetadataXml, error: errors.idpMetadataXml, placeholder: "<?xml version=\"1.0\"?>...", rows: 5, hint: "Paste raw SAML metadata XML if URL is unavailable." })}

          <hr style="border:none;border-top:1px solid var(--color-border,#e5e7eb);margin:1.5rem 0" />
          <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem">Security &amp; Protocol</h3>

          ${renderNameIdFormatField({ value: values.nameIdFormat, error: errors.nameIdFormat })}
          ${renderCheckboxField({ label: "Request Signed", name: "requestSigned", checked: Boolean(values.requestSigned), hint: "SP signs authentication requests" })}
          ${renderCheckboxField({ label: "Want Response Signed", name: "wantResponseSigned", checked: Boolean(values.wantResponseSigned), hint: "SP expects the SAML response to be signed" })}
          ${renderCheckboxField({ label: "Want Assertion Signed", name: "wantAssertionSigned", checked: Boolean(values.wantAssertionSigned), hint: "SP expects the SAML assertion to be signed" })}
          ${renderField({ label: "Logout URL (SLO)", name: "logoutUrl", value: values.logoutUrl, error: errors.logoutUrl, placeholder: "https://your-app.example.com/logout" })}

          <hr style="border:none;border-top:1px solid var(--color-border,#e5e7eb);margin:1.5rem 0" />
          <h3 style="font-size:1rem;font-weight:600;margin:0 0 1rem">Attributes &amp; Notes</h3>

          ${renderTextareaField({ label: "Required Attributes", name: "requiredAttributes", value: values.requiredAttributes, error: errors.requiredAttributes, placeholder: "mail\ngivenName\nsn", rows: 4, hint: "One attribute name per line." })}
          ${renderTextareaField({ label: "Access Control Notes", name: "accessControlNotes", value: values.accessControlNotes, error: errors.accessControlNotes, placeholder: "e.g. Restricted to group X, requires MFA...", rows: 3 })}

          <div class="sp-form__actions">
            <button type="submit" class="button button-compact">Save changes</button>
            <a class="button-secondary button-compact" href="/saml/service-providers">Cancel</a>
          </div>
        </form>

        <form class="sp-form__delete" method="post" action="/saml/service-providers/${encodeURIComponent(sp.id)}/delete" data-confirm="Delete this SAML Service Provider?">
          <button type="submit" class="danger-button">Delete</button>
        </form>
      </div>
    </section>
  `;

  return renderLayout({
    title: "Edit SAML Service Provider — Ez-Access Debug",
    activeNav: "saml-service-providers",
    body
  });
}
