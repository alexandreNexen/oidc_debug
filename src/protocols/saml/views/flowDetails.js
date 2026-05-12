import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader } from "../../../common/views/layout.js";

function formatDate(v) {
  return v ? new Date(v).toLocaleString("fr-FR") : "Not available";
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "Running";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

const INTERNAL_RAW_FIELDS = new Set(["raw_type", "is_real_http_exchange", "source"]);

function filterRawForDisplay(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return obj;
  return Object.fromEntries(
    Object.entries(obj).filter(([k]) => !INTERNAL_RAW_FIELDS.has(k))
  );
}

function encodeRawData(value) {
  if (!value || (typeof value === "object" && Object.keys(value).length === 0)) return "";
  return Buffer.from(JSON.stringify(filterRawForDisplay(value), null, 2), "utf8").toString("base64");
}

// ---- Status badge helpers ----

const BADGE_SUCCESS = new Set(["yes", "received", "present", "sent", "valid", "success", "match", "ok", "decoded: success"]);
const BADGE_ERROR = new Set(["no", "missing", "failed", "mismatch", "error", "failure", "invalid"]);
const BADGE_NEUTRAL = new Set([
  "not implemented", "not checked", "not extracted", "skipped", "none",
  "disabled", "not sent", "pending", "not performed", "not available",
  "missing signature", "missing certificate", "unsupported"
]);

function badge(value) {
  if (value === null || value === undefined || value === "") return `<span class="muted">—</span>`;
  if (typeof value === "number") {
    const str = String(value);
    if (value >= 200 && value < 300) return `<span class="badge badge--success">${str}</span>`;
    if (value >= 400) return `<span class="badge badge--error">${str}</span>`;
    return `<span>${str}</span>`;
  }
  const str = String(value);
  const low = str.toLowerCase().trim();

  if (BADGE_SUCCESS.has(low)
    || low.includes("generated + sent")
    || low.includes("challenge sent")
    || low.includes("decoded: success")
    || low === "success") {
    return `<span class="badge badge--success">${escapeHtml(str)}</span>`;
  }
  // Check neutral BEFORE the startsWith("missing") error catch — "missing signature" / "missing certificate" are neutral
  if (BADGE_NEUTRAL.has(low)
    || low.includes("not implemented")
    || low.includes("not checked")
    || low.includes("not extracted")
    || low.includes("not performed")) {
    return `<span class="badge badge--neutral">${escapeHtml(str)}</span>`;
  }
  if (BADGE_ERROR.has(low) || low.startsWith("missing") || low === "failure") {
    return `<span class="badge badge--error">${escapeHtml(str)}</span>`;
  }
  return `<span>${escapeHtml(str)}</span>`;
}

function plain(v) {
  if (v === null || v === undefined || v === "") return `<span class="muted">—</span>`;
  return `<span>${escapeHtml(String(v))}</span>`;
}

function code(v) {
  if (!v) return `<span class="muted">—</span>`;
  return `<code class="code-inline">${escapeHtml(String(v))}</code>`;
}

function pills(arr) {
  if (!Array.isArray(arr) || arr.length === 0) return `<span class="muted">—</span>`;
  return arr.map((item) => `<span class="badge badge--neutral">${escapeHtml(String(item))}</span>`).join(" ");
}

// ---- Layout helpers ----

function dl(rows) {
  const filtered = rows.filter(Boolean);
  if (!filtered.length) return `<p class="muted">No data available.</p>`;
  return `<dl class="flow-data-list">${filtered.join("")}</dl>`;
}

function row(label, html) {
  return `<div class="flow-data-list__row"><dt>${escapeHtml(label)}</dt><dd>${html}</dd></div>`;
}

function rawBtn(title, stepName, type, rawData) {
  if (!rawData) return "";
  const label = type === "request" ? "Request" : "Response";
  return `<button class="panel-action-button" type="button"
    data-raw-open
    data-raw-title="${escapeHtml(title)}"
    data-raw-step="${escapeHtml(stepName)}"
    data-raw-type="${escapeHtml(label)}"
    data-raw-json="${escapeHtml(encodeRawData(rawData))}"
  >Raw</button>`;
}

function sectionHead(title, summary) {
  return `
    <div class="flow-section__header">
      <h2 class="flow-section__title">${escapeHtml(title)}</h2>
      <p class="flow-section__summary">${escapeHtml(summary)}</p>
    </div>`;
}

function exchangePanel(title, rawButton, content, errorMsg) {
  return `
    <article class="flow-detail-panel">
      <header>
        <h3>${escapeHtml(title)}</h3>
        ${rawButton}
      </header>
      ${content}
      ${errorMsg ? `<div class="form-banner form-banner--error" style="margin-top:12px">${escapeHtml(String(errorMsg))}</div>` : ""}
    </article>`;
}

function analysisPanel(title, rawButton, content) {
  return `
    <article class="flow-detail-panel">
      <header>
        <h3>${escapeHtml(title)}</h3>
        ${rawButton}
      </header>
      ${content}
    </article>`;
}

// ---- Section navigation ----

function sectionDot(status) {
  const cls = status === "success" ? "section-tab__dot--success"
    : status === "error" ? "section-tab__dot--error"
    : status === "running" ? "section-tab__dot--running"
    : "";
  return `<span class="section-tab__dot${cls ? ` ${cls}` : ""}" aria-hidden="true"></span>`;
}

function renderSectionNav(tabs) {
  return `
    <nav class="section-tabs" data-section-nav aria-label="Flow sections">
      ${tabs.map((tab, i) => `
        ${i > 0 ? `<span class="section-tabs__sep" aria-hidden="true">→</span>` : ""}
        <button
          class="section-tab${i === 0 ? " is-active" : ""}"
          type="button"
          data-section-tab="${escapeHtml(tab.id)}"
          aria-selected="${i === 0 ? "true" : "false"}"
        >
          <span class="section-tab__num">${tab.num}</span>
          ${escapeHtml(tab.label)}
          ${sectionDot(tab.status)}
        </button>
      `).join("")}
    </nav>`;
}

function computeSectionTabs(steps) {
  const byName = new Map(steps.map((s) => [s.stepName, s]));
  const authn = byName.get("authn_request_created");
  const redirect = byName.get("redirect_to_idp");
  const samlResp = byName.get("saml_response_received");
  const decoded = byName.get("saml_response_decoded");

  let exchangeStatus = "pending";
  if (authn?.status === "error" || redirect?.status === "error" || samlResp?.status === "error") {
    exchangeStatus = "error";
  } else if (samlResp?.status === "success") {
    exchangeStatus = "success";
  } else if (authn?.status === "success") {
    exchangeStatus = "running";
  }

  const identityStatus = decoded?.status || "pending";

  return [
    { id: "auth-exchange", label: "Authentication exchange", num: 1, status: exchangeStatus },
    { id: "identity", label: "Identity assertion", num: 2, status: identityStatus }
  ];
}

// ---- Section 1: Authentication exchange ----

function renderAuthenticationExchange(steps) {
  const authn = steps.find((s) => s.stepName === "authn_request_created");
  const redirect = steps.find((s) => s.stepName === "redirect_to_idp");
  const acs = steps.find((s) => s.stepName === "acs_callback_received");
  const samlResp = steps.find((s) => s.stepName === "saml_response_received");
  const decoded = steps.find((s) => s.stepName === "saml_response_decoded");

  const aRd = authn?.requestData || {};
  const rRd = redirect?.requestData || {};
  const acRd = acs?.requestData || {};
  const sRd = samlResp?.requestData || {};
  const sRResp = samlResp?.responseData || {};
  const dRd = decoded?.requestData || {};
  const dResp = decoded?.responseData || {};

  const notStarted = !authn || authn.status === "pending";
  const responseReceived = Boolean(samlResp && samlResp.status !== "pending");

  const binding = rRd.binding || aRd.binding_used_for_request || "";
  const samlRequestPresent = rRd.saml_request || (aRd.saml_request_encoded_size_bytes ? "present" : "");

  const requestContent = notStarted
    ? `<p class="muted">Not started.</p>`
    : dl([
        row("AuthnRequest generated", badge(authn.status === "success" ? "yes" : "no")),
        row("SP Entity ID", plain(aRd.sp_entity_id)),
        row("ACS URL", plain(aRd.acs_url)),
        row("IdP SSO URL", plain(aRd.destination)),
        row("Request ID", plain(aRd.request_id)),
        row("Issue instant", plain(aRd.issue_instant)),
        row("NameID format", plain(aRd.name_id_format || "(unspecified)")),
        binding ? row("Binding", plain(binding)) : null,
        row("SAMLRequest", badge(samlRequestPresent || "present")),
        row("RelayState", badge(aRd.relay_state)),
        row("Request signature", badge("not implemented"))
      ]);

  const responseContent = !responseReceived
    ? `<p class="muted">${notStarted ? "Not started." : "Waiting for SAMLResponse…"}</p>`
    : dl([
        row("SAMLResponse received", badge(sRd.saml_response || acRd.saml_response)),
        row("RelayState received", badge(acRd.relay_state)),
        row("Response decoded", badge(sRResp.decoded)),
        decoded ? row("Issuer (IdP)", plain(dRd.response_issuer)) : null,
        decoded ? row("InResponseTo", plain(dRd.in_response_to)) : null,
        decoded ? row("Destination", plain(dRd.destination)) : null,
        decoded ? row("SAML Status", badge(dResp.saml_status)) : null,
        decoded ? row("Status code", plain(dRd.status_code)) : null,
        decoded && dRd.status_message && dRd.status_message !== "(not extracted)"
          ? row("Status message", plain(dRd.status_message)) : null,
        decoded ? row("Status detail", badge(dRd.status_detail)) : null
      ]);

  const respRawData = samlResp?.rawResponseData || decoded?.rawRequestData;
  const authnError = authn?.errorData?.error || redirect?.errorData?.error;

  return `
    <section class="flow-section" data-section-panel="auth-exchange">
      ${sectionHead("Authentication exchange", "The SP prepares an AuthnRequest to ask the IdP to authenticate a user. The IdP sends back a SAMLResponse to the SP.")}
      <div class="exchange-grid">
        ${exchangePanel("Request",
          rawBtn("Raw AuthnRequest", "authn_request_created", "request", authn?.rawRequestData),
          requestContent,
          authnError)}
        ${exchangePanel("Response",
          rawBtn("Raw SAMLResponse", "saml_response_received", "response", respRawData),
          responseContent,
          null)}
      </div>
    </section>`;
}

// ---- Section 2: Identity assertion ----

function renderIdentityAssertion(steps) {
  const decoded = steps.find((s) => s.stepName === "saml_response_decoded");
  const resp = decoded?.responseData || {};
  const diagnostics = resp.diagnostic_comparisons || {};

  if (!decoded || decoded.status === "pending") {
    return `
      <section class="flow-section" data-section-panel="identity">
        ${sectionHead("Identity assertion", "The SP analyzes the SAMLResponse to understand what identity information was transmitted by the IdP.")}
        <p class="muted">No assertion data available yet.</p>
      </section>`;
  }

  const rawButton = rawBtn("Raw parsed SAMLResponse", "saml_response_decoded", "response", decoded.rawResponseData);
  const userIdentified = resp.name_id_present === "yes" && resp.assertion_present === "yes" ? "yes" : "no";

  const identitySummary = analysisPanel("Identity summary", rawButton, dl([
    row("Assertion present", badge(resp.assertion_present)),
    row("User identified", badge(userIdentified)),
    row("NameID present", badge(resp.name_id_present)),
    row("NameID format", plain(resp.name_id_format)),
    row("NameID", resp.name_id_preview ? plain(resp.name_id_preview) : badge("missing")),
    row("Attributes received", plain(String(resp.attributes_count ?? 0))),
    row("Attribute names", pills(resp.attribute_names))
  ]));

  const consistencyChecks = analysisPanel("Consistency checks", "", dl([
    row("InResponseTo vs Request ID", badge(diagnostics.in_response_to_vs_request_id)),
    row("Destination vs ACS URL", badge(diagnostics.destination_vs_acs_url)),
    row("Audience vs SP Entity ID", badge(diagnostics.audience_vs_sp_entity_id)),
    row("Temporal conditions", badge(diagnostics.temporal_conditions))
  ]));

  const sigNote = resp.verification_note
    ? `<p class="muted" style="margin:8px 0 0">${escapeHtml(resp.verification_note)}</p>`
    : "";
  const signatureStatus = analysisPanel("Signature status", "", dl([
    row("Response signature", badge(resp.response_signature_present || "not extracted")),
    row("Response verification", badge(resp.response_signature_verification || "not checked")),
    row("Assertion signature", badge(resp.assertion_signature_present || "not extracted")),
    row("Assertion verification", badge(resp.assertion_signature_verification || "not checked")),
    row("Signature verification result", badge(resp.signature_verification_result || "not checked"))
  ]) + sigNote);

  return `
    <section class="flow-section" data-section-panel="identity">
      ${sectionHead("Identity assertion", "The SP analyzes the SAMLResponse to understand what identity information was transmitted by the IdP.")}
      <div class="analysis-grid">
        ${identitySummary}
        ${consistencyChecks}
        ${signatureStatus}
      </div>
    </section>`;
}

// ---- Page ----

export function renderSamlFlowDetailsPage({ flow, serviceProvider, steps = [], flash }) {
  const status = flow.statusBadge || { label: "Running", tone: "neutral" };
  const tabs = computeSectionTabs(steps);

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Flow Details",
      description: `${serviceProvider.name || "Service Provider"} · ${status.label} · ${flow.id}`,
      actions: renderIconBtn({ icon: "return", label: "Back to result", href: `/saml/flows/${encodeURIComponent(flow.id)}`, variant: "neutral", showLabel: true })
    })}

    <section class="card">
      <div class="card__body">
        <dl class="flow-meta">
          <div>
            <dt>Protocol</dt>
            <dd><span class="badge badge--neutral">SAML</span></dd>
          </div>
          <div>
            <dt>Service Provider</dt>
            <dd>${escapeHtml(serviceProvider.name || "Unknown")}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>${flow.environmentLabel
              ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>`
              : `<span class="badge badge--warning">Environment missing</span>`}</dd>
          </div>
          <div>
            <dt>SP Entity ID</dt>
            <dd><code class="code-inline">${escapeHtml(flow.runtime?.spEntityId || "")}</code></dd>
          </div>
          <div>
            <dt>Result</dt>
            <dd><span class="badge badge--${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span></dd>
          </div>
          <div>
            <dt>Flow ID</dt>
            <dd><code class="code-inline">${escapeHtml(flow.id)}</code></dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>${escapeHtml(formatDate(flow.startedAt))}</dd>
          </div>
          <div>
            <dt>Duration</dt>
            <dd>${escapeHtml(formatDuration(flow.durationMs))}</dd>
          </div>
          <div>
            <dt>Failed step</dt>
            <dd>${flow.failedStep ? escapeHtml(flow.failedStep) : `<span class="muted">None</span>`}</dd>
          </div>
        </dl>
      </div>
    </section>

    <div data-sections-layout>
      ${renderSectionNav(tabs)}
      ${renderAuthenticationExchange(steps)}
      ${renderIdentityAssertion(steps)}
    </div>

    <div class="modal-backdrop" data-raw-modal hidden>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="raw-modal-title">
        <header class="modal__header">
          <div>
            <h2 id="raw-modal-title">Raw data</h2>
            <p class="modal__subtitle muted" data-raw-modal-subtitle></p>
          </div>
        </header>
        <div class="modal__body">
          <pre class="raw-json-block" data-raw-modal-body>No raw data recorded for this step.</pre>
        </div>
        <footer class="modal__footer">
          ${renderIconBtn({ icon: "copy", label: "Copy", variant: "neutral", attr: "data-raw-copy" })}
          ${renderIconBtn({ icon: "return", label: "Close", variant: "neutral", attr: "data-raw-close" })}
        </footer>
      </section>
    </div>`;

  return renderLayout({
    title: "Flow details — Ez-Access SAML Debug",
    activeNav: "saml-service-providers",
    body
  });
}
