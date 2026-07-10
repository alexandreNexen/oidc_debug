import React from "react";
import JsonBlock from "./JsonBlock.jsx";
import StatusBadge from "./StatusBadge.jsx";

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function badgeToneForStatus(status) {
  if (status === "success") return "success";
  if (status === "error" || status === "failed") return "error";
  if (status === "pending" || status === "running") return "info";
  return "neutral";
}

function toneForHttpStatus(status) {
  const code = Number(status);
  if (!Number.isFinite(code)) return "neutral";
  if (code >= 200 && code < 300) return "success";
  if (code >= 400) return "error";
  return "info";
}

export default function FlowStepDetail({ step }) {
  if (!step) return null;

  const status = step.status || "pending";
  const badge = step.badge || null;
  const badgeLabel = (badge && badge.label) || status;
  const badgeTone = (badge && badge.tone) || badgeToneForStatus(status);

  return (
    <section className="step">
      <header className="step-header">
        <div className="step-title-block">
          <h3 className="step-title">{fmt(step.stepName)}</h3>
          <div className="step-meta muted">
            <span>{fmt(step.httpMethod)}</span>
            <span>· <code className="code">{fmt(step.endpoint)}</code></span>
            {step.httpStatus !== null && step.httpStatus !== undefined ? (
              <span>
                · <StatusBadge label={`HTTP ${step.httpStatus}`} tone={toneForHttpStatus(step.httpStatus)} />
              </span>
            ) : null}
          </div>
          <div className="step-meta muted">
            <span>created {fmt(step.createdAt)}</span>
            {step.completedAt ? <span>· completed {fmt(step.completedAt)}</span> : null}
          </div>
        </div>
        <StatusBadge label={badgeLabel} tone={badgeTone} />
      </header>

      {step.errorData ? (
        <div className="step-section step-section--error">
          <JsonBlock label="errorData" value={step.errorData} defaultExpanded={true} />
        </div>
      ) : null}

      <div className="step-section">
        <JsonBlock label="requestData" value={step.requestData} />
      </div>

      <div className="step-section">
        <JsonBlock label="responseData" value={step.responseData} />
      </div>

      {step.rawRequestData ? (
        <div className="step-section">
          <JsonBlock
            label={
              step.rawRequestNature
                ? `rawRequestData — ${step.rawRequestNature}`
                : "rawRequestData"
            }
            value={step.rawRequestData}
          />
        </div>
      ) : null}

      {step.rawResponseData ? (
        <div className="step-section">
          <JsonBlock
            label={
              step.rawResponseNature
                ? `rawResponseData — ${step.rawResponseNature}`
                : "rawResponseData"
            }
            value={step.rawResponseData}
          />
        </div>
      ) : null}

      {step.rawAnalysisData ? (
        <div className="step-section">
          <JsonBlock label="rawAnalysisData" value={step.rawAnalysisData} />
        </div>
      ) : null}
    </section>
  );
}
