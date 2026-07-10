import React from "react";
import Card from "./Card.jsx";
import StatusBadge from "./StatusBadge.jsx";

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function statusTone(status) {
  if (status === "ready") return "success";
  if (status === "incomplete") return "warning";
  if (status === "invalid") return "error";
  return "neutral";
}

function renderOidcRow(sp) {
  return (
    <li key={sp.id} className="list-row">
      <div className="list-main">
        <a href={`/oidc/service-providers/${encodeURIComponent(sp.id)}/edit`} className="list-title">
          {fmt(sp.name) || fmt(sp.clientId) || fmt(sp.id)}
        </a>
        <div className="list-meta muted">
          <code className="code">{fmt(sp.clientId)}</code>
          <span>· {fmt(sp.clientType)}</span>
          <span>· {fmt(sp.environmentLabel || sp.environment)}</span>
        </div>
      </div>
      <div className="list-side">
        <StatusBadge label={fmt(sp.status)} tone={statusTone(sp.status)} />
        <span className={`badge badge--${sp.secretConfigured ? "success" : "neutral"}`}>
          {sp.secretConfigured ? "secret configured" : "no secret"}
        </span>
      </div>
    </li>
  );
}

function renderSamlRow(sp) {
  return (
    <li key={sp.id} className="list-row">
      <div className="list-main">
        <a href={`/saml/service-providers/${encodeURIComponent(sp.id)}/edit`} className="list-title">
          {fmt(sp.name) || fmt(sp.spEntityId) || fmt(sp.id)}
        </a>
        <div className="list-meta muted">
          <code className="code">{fmt(sp.spEntityId)}</code>
          <span>· {fmt(sp.environmentLabel || sp.environment)}</span>
        </div>
        {sp.acsUrl ? (
          <div className="list-meta muted">
            ACS: <code className="code">{sp.acsUrl}</code>
          </div>
        ) : null}
      </div>
      <div className="list-side">
        <StatusBadge label={fmt(sp.status)} tone={statusTone(sp.status)} />
      </div>
    </li>
  );
}

export default function ServiceProvidersPanel({ protocol, items }) {
  const list = Array.isArray(items) ? items : [];
  const listHref = protocol === "SAML" ? "/saml/service-providers" : "/oidc/service-providers";
  const title = protocol === "SAML" ? "SAML Service Providers" : "OIDC Service Providers";

  return (
    <Card
      title={title}
      subtitle={`${list.length} configured`}
      actions={
        <a href={listHref} className="btn-link">Open list</a>
      }
    >
      {list.length === 0 ? (
        <p className="muted empty">No {protocol} Service Provider configured.</p>
      ) : (
        <ul className="list">
          {list.map((sp) => (protocol === "SAML" ? renderSamlRow(sp) : renderOidcRow(sp)))}
        </ul>
      )}
    </Card>
  );
}
