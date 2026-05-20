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

const BADGE_SUCCESS = new Set(["yes", "received", "present", "sent", "valid", "success", "match", "ok", "decoded: success", "complete", "available", "generated", "used"]);
const BADGE_ERROR = new Set(["no", "missing", "failed", "mismatch", "error", "failure", "invalid"]);
const BADGE_NEUTRAL = new Set([
  "not implemented", "not checked", "not extracted", "skipped", "none",
  "disabled", "not sent", "pending", "not performed", "not available",
  "missing signature", "missing certificate", "unsupported", "not_checked",
  "unavailable", "incomplete", "present / not evaluated", "missing_signature",
  "missing_certificate"
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
    || low.includes("not_checked")
    || low.includes("not extracted")
    || low.includes("not performed")
    || low.includes("not evaluated")) {
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

function muted(v) {
  if (v === null || v === undefined || v === "") return "";
  return `<p class="muted" style="margin:6px 0 0">${escapeHtml(String(v))}</p>`;
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

function diagnosticStatus(value, { missingAs = "missing" } = {}) {
  const low = String(value || "").toLowerCase().trim();
  if (!low || low === "(not found)" || low === "(not extracted)") return missingAs;
  if (["valid", "match", "success", "ok", "complete"].includes(low)) return "valid";
  if (["missing", "not found"].includes(low)) return missingAs;
  return "invalid";
}

function diagnosticReason(value, fallback = "") {
  const low = String(value || "").toLowerCase().trim();
  if (!low || ["valid", "match", "success", "ok", "complete"].includes(low)) return "";
  return fallback || String(value);
}

function statusWithDetail(status, detail) {
  return `${badge(status)}${detail ? muted(detail) : ""}`;
}

function shortNameIdFormat(value) {
  if (!value || value === "(not present)") return value || "(not present)";
  const str = String(value);
  const marker = "nameid-format:";
  const idx = str.toLowerCase().lastIndexOf(marker);
  if (idx !== -1) return str.slice(idx + marker.length);
  return str.split(":").pop() || str;
}

function attributesSummary(count, names) {
  const total = Number(count || 0);
  if (!total) return badge("none");
  const nameList = Array.isArray(names) && names.length > 0 ? `: ${names.join(", ")}` : "";
  return plain(`${total}${nameList}`);
}

function requestSignatureStatus(authnRequestData = {}) {
  const explicit = authnRequestData.request_signature || authnRequestData.signature;
  if (explicit) return explicit;
  if (authnRequestData.binding_used_for_request === "not implemented") return "not implemented";
  return "not implemented";
}

function diagnosticsValue(resp = {}, key) {
  return resp.diagnostic_comparisons?.[key] || "";
}

function signatureSummary(resp = {}) {
  const result = resp.signature_verification_result || "unavailable";
  if (result === "valid") return "valid";
  if (result === "invalid") return "invalid";
  if (resp.response_signature_present === "present" || resp.assertion_signature_present === "present") return "unavailable";
  return "unavailable";
}

function trustedCertificateSummary(resp = {}) {
  if (Number(resp.idp_certificates_used || 0) > 0) return "used";
  if (resp.trust_validation === "failed") return "missing";
  return "unavailable";
}

function trustMessage(resp = {}) {
  const trust = resp.trust_validation || "incomplete";
  const errors = Array.isArray(resp.trust_validation_errors) ? resp.trust_validation_errors.filter(Boolean) : [];
  const warnings = Array.isArray(resp.trust_validation_warnings) ? resp.trust_validation_warnings.filter(Boolean) : [];

  if (trust === "complete") {
    return "Signature verification uses the trusted IdP metadata certificate.";
  }
  if (trust === "failed") {
    return `Trust validation failed: ${errors.join(" ") || "One or more validation checks failed."}`;
  }
  return `Trust validation incomplete: ${warnings.join(" ") || errors.join(" ") || resp.verification_note || "The SAML response was not fully verified against trusted IdP metadata."}`;
}

function securityChecksSummary(resp = {}, diagnostics = {}) {
  const checks = [
    resp.issuer_validation || diagnostics.issuer_validation,
    resp.temporal_validation || diagnostics.temporal_conditions,
    resp.xsw_protection || diagnostics.xsw_protection,
    resp.replay_validation
  ];
  return checks.every((check) => diagnosticStatus(check, { missingAs: "invalid" }) === "valid") ? "valid" : "invalid";
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

function identitySummaryRaw(decoded) {
  const assertion = decoded?.rawResponseData?.assertion || {};
  if (!decoded?.rawResponseData && !decoded?.responseData) return null;

  const resp = decoded.responseData || {};
  const nameIdPresent = assertion.name_id_present || resp.name_id_present || "not extracted";
  return {
    raw_type: "Identity assertion summary redacted",
    timestamp: decoded.rawResponseData?.timestamp || decoded.completedAt || null,
    assertion: {
      present: assertion.present || resp.assertion_present || "not extracted",
      subject_present: assertion.subject_present || resp.subject_present || "not extracted",
      name_id_present: nameIdPresent,
      name_id_preview: assertion.name_id_preview || resp.name_id_preview || (nameIdPresent === "yes" ? "received / redacted" : "(not present)"),
      name_id_hash: assertion.name_id_hash || resp.name_id_hash || "",
      name_id_format: assertion.name_id_format || resp.name_id_format || "(not present)",
      attributes_count: assertion.attributes_count ?? resp.attributes_count ?? 0,
      attribute_names: assertion.attribute_names || resp.attribute_names || [],
      attributes_redacted: assertion.attributes_redacted || resp.attributes_redacted || {}
    }
  };
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
  const relayState = aRd.relay_state || rRd.relay_state || "missing";
  const requestCorrelation = decoded
    ? diagnosticStatus(diagnosticsValue(dResp, "in_response_to_vs_request_id"))
    : "missing";
  const destinationStatus = decoded
    ? diagnosticStatus(diagnosticsValue(dResp, "destination_vs_acs_url"))
    : "missing";
  const correlationDetail = requestCorrelation === "invalid"
    ? `Expected Request ID: ${aRd.request_id || "(not available)"}; received InResponseTo: ${dRd.in_response_to || "(not found)"}`
    : "";
  const destinationDetail = destinationStatus === "invalid"
    ? `Expected ACS URL: ${aRd.acs_url || "(not available)"}; received Destination: ${dRd.destination || "(not found)"}`
    : "";
  const samlStatus = dResp.saml_status || (decoded?.status === "error" ? "Failure" : "");
  const samlStatusDetail = samlStatus && samlStatus !== "Success"
    ? [
        dRd.status_code ? `Status code: ${dRd.status_code}` : "",
        dRd.status_message && dRd.status_message !== "(not extracted)" ? `Status message: ${dRd.status_message}` : "",
        dRd.status_detail && dRd.status_detail !== "missing" ? `Status detail: ${dRd.status_detail}` : ""
      ].filter(Boolean).join("; ")
    : "";

  const requestContent = notStarted
    ? `<p class="muted">Not started.</p>`
    : dl([
        row("AuthnRequest", badge(authn.status === "success" ? "generated" : "missing")),
        binding ? row("Binding", plain(binding)) : null,
        row("SP Entity ID", plain(aRd.sp_entity_id)),
        row("ACS URL", plain(aRd.acs_url)),
        row("IdP SSO URL", plain(aRd.destination)),
        row("RelayState", badge(relayState === "present" ? "present" : "missing")),
        row("Request signature", badge(requestSignatureStatus(aRd)))
      ]);

  const responseContent = !responseReceived
    ? `<p class="muted">${notStarted ? "Not started." : "Waiting for SAMLResponse…"}</p>`
    : dl([
        row("SAMLResponse", badge(sRd.saml_response || acRd.saml_response || "missing")),
        row("Decoded", badge(sRResp.decoded === "success" ? "success" : "failed")),
        decoded ? row("SAML Status", statusWithDetail(samlStatus || "missing", samlStatusDetail)) : null,
        decoded ? row("Issuer", plain(dRd.response_issuer)) : null,
        decoded ? row("Request correlation", statusWithDetail(requestCorrelation, correlationDetail)) : null,
        decoded ? row("Destination", statusWithDetail(destinationStatus, destinationDetail)) : null
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

  const rawButton = rawBtn("Raw identity summary", "saml_response_decoded", "response", identitySummaryRaw(decoded));
  const userIdentified = resp.name_id_present === "yes" && resp.assertion_present === "yes" ? "yes" : "no";
  const nameIdStatus = resp.name_id_present === "yes" ? (resp.name_id_preview || "received / redacted") : "missing";

  const requestCorrelationStatus = diagnosticStatus(diagnostics.in_response_to_vs_request_id, { missingAs: "invalid" });
  const destinationStatus = diagnosticStatus(diagnostics.destination_vs_acs_url, { missingAs: "invalid" });
  const audienceStatus = diagnosticStatus(diagnostics.audience_vs_sp_entity_id, { missingAs: "invalid" });
  const issuerStatus = diagnosticStatus(diagnostics.issuer_validation || resp.issuer_validation, { missingAs: "invalid" });
  const timingStatus = diagnosticStatus(diagnostics.temporal_conditions || resp.temporal_validation, { missingAs: "invalid" });
  const securityStatus = securityChecksSummary(resp, diagnostics);

  const identitySummary = analysisPanel("Identity summary", rawButton, dl([
    row("User identified", badge(userIdentified)),
    row("NameID", resp.name_id_present === "yes" ? plain(nameIdStatus) : badge(nameIdStatus)),
    row("NameID format", plain(shortNameIdFormat(resp.name_id_format))),
    row("Attributes", attributesSummary(resp.attributes_count, resp.attribute_names))
  ]));

  const consistencyChecks = analysisPanel("Protocol / security summary", "", dl([
    row("Request correlation", statusWithDetail(
      requestCorrelationStatus,
      diagnosticReason(diagnostics.in_response_to_vs_request_id)
    )),
    row("Destination", statusWithDetail(
      destinationStatus,
      diagnosticReason(diagnostics.destination_vs_acs_url)
    )),
    row("Audience", statusWithDetail(
      audienceStatus,
      diagnosticReason(diagnostics.audience_vs_sp_entity_id)
    )),
    row("Issuer", statusWithDetail(
      issuerStatus,
      diagnosticReason(diagnostics.issuer_validation || resp.issuer_validation)
    )),
    row("Timing", statusWithDetail(
      timingStatus,
      diagnosticReason(diagnostics.temporal_conditions || resp.temporal_validation)
    )),
    row("Security checks", statusWithDetail(
      securityStatus,
      securityStatus === "invalid" ? diagnosticReason(diagnostics.xsw_protection || resp.xsw_protection || resp.replay_validation, "One or more security checks did not validate.") : ""
    ))
  ]));

  const trustStatus = analysisPanel("Trust status", "", dl([
    row("Trust validation", statusWithDetail(resp.trust_validation || "incomplete", trustMessage(resp))),
    row("Signatures", badge(signatureSummary(resp))),
    row("Trusted IdP certificate", badge(trustedCertificateSummary(resp))),
    row("Security checks", badge(securityStatus))
  ]));

  return `
    <section class="flow-section" data-section-panel="identity">
      ${sectionHead("Identity assertion", "The SP analyzes the SAMLResponse to understand what identity information was transmitted by the IdP.")}
      <div class="analysis-grid">
        ${identitySummary}
        ${consistencyChecks}
        ${trustStatus}
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
