import React from "react";
import Card from "./Card.jsx";
import StatusBadge from "./StatusBadge.jsx";

const FLOWS_DISPLAY_LIMIT = 10;

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function shortId(id) {
  const str = String(id || "");
  if (str.length <= 20) return str;
  return `${str.slice(0, 12)}…${str.slice(-4)}`;
}

function statusTone(badge, status) {
  if (badge && typeof badge.tone === "string") return badge.tone;
  if (status === "success") return "success";
  if (status === "failed" || status === "error") return "error";
  if (status === "running") return "info";
  return "neutral";
}

function statusLabel(badge, status) {
  if (badge && typeof badge.label === "string" && badge.label) return badge.label;
  return status || "—";
}

function detailHref(protocol, id) {
  const safeId = encodeURIComponent(id);
  if (protocol === "SAML") {
    return `/saml/flows/${safeId}`;
  }
  return `/oidc/flows/${safeId}`;
}

export default function FlowsPanel({ protocol, items }) {
  const list = Array.isArray(items) ? items.slice(0, FLOWS_DISPLAY_LIMIT) : [];
  const total = Array.isArray(items) ? items.length : 0;
  const title = protocol === "SAML" ? "Recent SAML flows" : "Recent OIDC flows";
  const viteListHref = protocol === "SAML" ? "/saml/flows" : "/oidc/flows";
  const subtitle =
    total > FLOWS_DISPLAY_LIMIT
      ? `Showing ${list.length} of ${total}.`
      : `${total} flow${total === 1 ? "" : "s"}.`;

  return (
    <Card
      title={title}
      subtitle={subtitle}
      actions={
        <a href={viteListHref} className="btn-link">
          Open full list
        </a>
      }
    >
      {list.length === 0 ? (
        <p className="muted empty">No {protocol} flow recorded yet.</p>
      ) : (
        <ul className="list">
          {list.map((flow) => (
            <li key={flow.id} className="list-row">
              <div className="list-main">
                <a href={detailHref(protocol, flow.id)} className="list-title">
                  <code className="code">{shortId(flow.id)}</code>
                </a>
                <div className="list-meta muted">
                  <span>{fmt(flow.serviceProviderName) || fmt(flow.serviceProviderId)}</span>
                  <span>· started {fmt(flow.startedAt)}</span>
                  {flow.completedAt ? <span>· completed {fmt(flow.completedAt)}</span> : null}
                </div>
                {flow.errorCode || flow.errorDescription ? (
                  <div className="list-meta list-meta--error">
                    <span>{fmt(flow.errorCode)}</span>
                    {flow.errorDescription ? <span> · {fmt(flow.errorDescription)}</span> : null}
                  </div>
                ) : null}
              </div>
              <div className="list-side">
                <StatusBadge
                  label={statusLabel(flow.statusBadge, flow.status)}
                  tone={statusTone(flow.statusBadge, flow.status)}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
