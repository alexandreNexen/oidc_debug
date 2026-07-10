import React from "react";
import Card from "./Card.jsx";

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

export default function HealthPanel({ health, fetchedAt }) {
  if (!health) return null;

  const oidc = health.counts?.oidc || { serviceProviders: 0, flows: 0 };
  const saml = health.counts?.saml || { serviceProviders: 0, flows: 0 };

  return (
    <Card
      title="Backend health"
      subtitle="Live counts from /api/health"
    >
      <dl className="kv">
        <div className="kv-row">
          <dt>Status</dt>
          <dd>
            <span className={`badge badge--${health.status === "ok" ? "success" : "error"}`}>
              {fmt(health.status)}
            </span>
          </dd>
        </div>
        <div className="kv-row">
          <dt>Node env</dt>
          <dd>{fmt(health.nodeEnv)}</dd>
        </div>
        <div className="kv-row">
          <dt>Redirect URI</dt>
          <dd><code className="code">{fmt(health.redirectUri)}</code></dd>
        </div>
        <div className="kv-row">
          <dt>Backend timestamp</dt>
          <dd>{fmt(health.timestamp)}</dd>
        </div>
        <div className="kv-row">
          <dt>Fetched at (client)</dt>
          <dd>{fmt(fetchedAt)}</dd>
        </div>
      </dl>

      <div className="counters">
        <div className="counter">
          <span className="counter-value">{oidc.serviceProviders}</span>
          <span className="counter-label">OIDC SPs</span>
        </div>
        <div className="counter">
          <span className="counter-value">{oidc.flows}</span>
          <span className="counter-label">OIDC flows</span>
        </div>
        <div className="counter">
          <span className="counter-value">{saml.serviceProviders}</span>
          <span className="counter-label">SAML SPs</span>
        </div>
        <div className="counter">
          <span className="counter-value">{saml.flows}</span>
          <span className="counter-label">SAML flows</span>
        </div>
      </div>
    </Card>
  );
}
