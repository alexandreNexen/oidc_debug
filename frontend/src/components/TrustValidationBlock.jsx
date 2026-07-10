import React from "react";
import Card from "./Card.jsx";
import JsonBlock from "./JsonBlock.jsx";
import StatusBadge from "./StatusBadge.jsx";

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function normalizedString(value) {
  return String(value || "").trim().toLowerCase();
}

function trustTone(value) {
  const v = normalizedString(value);
  if (v === "complete" || v === "valid") return "success";
  if (v === "incomplete" || v === "partial") return "warning";
  if (v === "failed" || v === "invalid" || v === "error") return "error";
  return "neutral";
}

function signatureTone(value) {
  const v = normalizedString(value);
  if (v === "valid") return "success";
  if (v === "invalid" || v === "error" || v === "failed") return "error";
  if (v === "missing signature" || v === "missing certificate" || v === "unsupported") return "warning";
  if (v === "not_checked" || v === "not checked" || v === "unavailable") return "neutral";
  return "neutral";
}

function presenceTone(value) {
  const v = normalizedString(value);
  if (v === "present") return "success";
  if (v === "missing") return "warning";
  return "neutral";
}

function pickDecodedStep(steps) {
  if (!Array.isArray(steps)) return null;
  return steps.find((step) => step && step.stepName === "saml_response_decoded") || null;
}

function toArray(value) {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined || value === "") return [];
  return [value];
}

function renderKv(label, node) {
  return (
    <div className="kv-row" key={label}>
      <dt>{label}</dt>
      <dd>{node}</dd>
    </div>
  );
}

function renderAttributes(response) {
  const names = Array.isArray(response.attribute_names) ? response.attribute_names : [];
  const count = typeof response.attributes_count === "number" ? response.attributes_count : names.length;
  if (count === 0) {
    return <span className="muted">no attributes</span>;
  }
  const preview = names.slice(0, 8).join(", ");
  const suffix = names.length > 8 ? `, +${names.length - 8} more` : "";
  return (
    <span>
      {count} — <code className="code">{preview}{suffix}</code>
    </span>
  );
}

export default function TrustValidationBlock({ steps }) {
  const decoded = pickDecodedStep(steps);
  const response = decoded?.responseData;
  if (!response || typeof response !== "object") {
    return null;
  }

  const errors = toArray(response.trust_validation_errors);
  const warnings = toArray(response.trust_validation_warnings);
  const checks = response.trust_validation_checks || null;
  const diagnostics = response.diagnostic_comparisons || null;

  return (
    <Card
      title="SAML trust &amp; signature verification"
      subtitle="Values as returned by the backend. Trust decisions are computed server-side; this view is read-only."
    >
      <dl className="kv">
        {renderKv(
          "Trust validation",
          <StatusBadge label={fmt(response.trust_validation)} tone={trustTone(response.trust_validation)} />
        )}
        {renderKv(
          "Signature verification result",
          <StatusBadge
            label={fmt(response.signature_verification_result)}
            tone={signatureTone(response.signature_verification_result)}
          />
        )}
        {response.verification_note
          ? renderKv("Verification note", <span>{fmt(response.verification_note)}</span>)
          : null}
        {typeof response.idp_certificates_used === "number"
          ? renderKv(
              "IdP signing certificates used",
              <span>{response.idp_certificates_used}</span>
            )
          : null}
      </dl>

      <dl className="kv">
        {renderKv(
          "Response signature present",
          <StatusBadge label={fmt(response.response_signature_present)} tone={presenceTone(response.response_signature_present)} />
        )}
        {renderKv(
          "Response signature verification",
          <StatusBadge label={fmt(response.response_signature_verification)} tone={signatureTone(response.response_signature_verification)} />
        )}
        {renderKv(
          "Assertion signature present",
          <StatusBadge label={fmt(response.assertion_signature_present)} tone={presenceTone(response.assertion_signature_present)} />
        )}
        {renderKv(
          "Assertion signature verification",
          <StatusBadge label={fmt(response.assertion_signature_verification)} tone={signatureTone(response.assertion_signature_verification)} />
        )}
      </dl>

      <dl className="kv">
        {renderKv("Issuer", <code className="code">{fmt(response.response_issuer || response.assertion_issuer)}</code>)}
        {renderKv("Destination", <code className="code">{fmt(response.destination)}</code>)}
        {renderKv("Audience", <code className="code">{fmt(response.audience)}</code>)}
        {renderKv("Recipient", <code className="code">{fmt(response.recipient)}</code>)}
        {renderKv("In response to", <code className="code">{fmt(response.in_response_to)}</code>)}
        {renderKv(
          "NameID",
          <span>
            <code className="code">{fmt(response.name_id_preview)}</code>
            {response.name_id_format ? <> · format <code className="code">{fmt(response.name_id_format)}</code></> : null}
            {response.name_id_hash ? <> · sha256_12 <code className="code">{fmt(response.name_id_hash)}</code></> : null}
          </span>
        )}
        {renderKv(
          "Session index",
          response.session_index && response.session_index.present ? (
            <span>
              <StatusBadge label="present" tone="success" />
              {response.session_index.sha256_12 ? <> · sha256_12 <code className="code">{response.session_index.sha256_12}</code></> : null}
            </span>
          ) : (
            <StatusBadge label="missing" tone="warning" />
          )
        )}
        {renderKv("Not before", <code className="code">{fmt(response.not_before)}</code>)}
        {renderKv("Not on or after", <code className="code">{fmt(response.not_on_or_after)}</code>)}
        {renderKv("SAML status", <code className="code">{fmt(response.saml_status || response.status_code)}</code>)}
        {response.status_message
          ? renderKv("Status message", <code className="code">{fmt(response.status_message)}</code>)
          : null}
        {renderKv("Attributes", renderAttributes(response))}
      </dl>

      {errors.length > 0 ? (
        <div className="alert alert--error" role="alert">
          <strong>Trust validation errors</strong>
          <ul className="plain-list">
            {errors.map((entry, index) => (
              <li key={index}>{fmt(typeof entry === "string" ? entry : JSON.stringify(entry))}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {warnings.length > 0 ? (
        <div className="alert alert--warning" role="status">
          <strong>Warnings</strong>
          <ul className="plain-list">
            {warnings.map((entry, index) => (
              <li key={index}>{fmt(typeof entry === "string" ? entry : JSON.stringify(entry))}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {response.attributes_redacted ? (
        <JsonBlock label="Attributes (from API)" value={response.attributes_redacted} />
      ) : null}

      {checks ? <JsonBlock label="Trust validation checks" value={checks} defaultExpanded={true} /> : null}

      {diagnostics ? <JsonBlock label="Diagnostic comparisons" value={diagnostics} /> : null}
    </Card>
  );
}
