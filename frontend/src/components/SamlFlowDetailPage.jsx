import React, { useCallback, useEffect, useState } from "react";
import { getSamlFlow, rerunSamlFlow } from "../api/client.js";
import Card from "./Card.jsx";
import FlowActionButton from "./FlowActionButton.jsx";
import FlowStepList from "./FlowStepList.jsx";
import JsonBlock from "./JsonBlock.jsx";
import StatusBadge from "./StatusBadge.jsx";
import TrustValidationBlock from "./TrustValidationBlock.jsx";

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
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

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "—";
  const value = Number(ms);
  if (!Number.isFinite(value)) return "—";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(2)} s`;
}

export default function SamlFlowDetailPage({ flowId }) {
  const [state, setState] = useState({
    status: "loading",
    error: "",
    errorStatus: 0,
    detail: null
  });
  const [actionError, setActionError] = useState("");

  const load = useCallback(async () => {
    setState({ status: "loading", error: "", errorStatus: 0, detail: null });
    try {
      const detail = await getSamlFlow(flowId);
      setState({ status: "ready", error: "", errorStatus: 0, detail });
    } catch (error) {
      const message = error && error.message ? error.message : "Unknown error while fetching the flow.";
      const errorStatus = error && typeof error.status === "number" ? error.status : 0;
      setState({ status: "error", error: message, errorStatus, detail: null });
    }
  }, [flowId]);

  useEffect(() => {
    load();
  }, [load]);

  const isLoading = state.status === "loading";
  const detail = state.detail;
  const flow = detail?.flow;
  const sp = detail?.serviceProvider;

  return (
    <div className="page">
      <header className="topbar">
        <div className="topbar-brand">
          <span className="topbar-title">Ez-Access Debug Console</span>
          <span className="topbar-badge">Vite frontend</span>
        </div>
        <nav className="topbar-nav" aria-label="Navigation">
          <a href="/">Dashboard</a>
          <a href="/oidc/service-providers">OIDC SPs</a>
          <a href="/saml/service-providers">SAML SPs</a>
        </nav>
      </header>

      <main className="shell">
        <section className="page-header">
          <div>
            <h1 className="page-title">SAML flow detail</h1>
            <p className="muted">
              Backed by <code className="code">/api/saml/flows/:id</code>. Displays exact
              diagnostic values (parsed SAMLResponse, assertion, signature verification,
              trust validation checks). Trust decisions are computed server-side; the
              frontend never re-evaluates them.
            </p>
            <p className="muted">
              Flow id: <code className="code">{fmt(flowId)}</code>
            </p>
          </div>
          <div className="page-actions">
            <FlowActionButton
              className="btn"
              onAction={() => rerunSamlFlow(flowId)}
              runningLabel="Rerunning…"
              onError={setActionError}
              title="Relance un flow SAML pour le même Service Provider"
            >
              Rerun flow
            </FlowActionButton>
            <button type="button" className="btn" onClick={load} disabled={isLoading} aria-busy={isLoading}>
              {isLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </section>

        {actionError ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de relancer le flow SAML.</strong>
            <p className="muted">{actionError}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={() => setActionError("")}>Fermer</button>
            </div>
          </div>
        ) : null}

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>
              {state.errorStatus === 404
                ? "SAML flow not found."
                : "Impossible de récupérer le flow depuis l'API."}
            </strong>
            <p className="muted">{state.error}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={load}>Réessayer</button>
              <a className="btn btn--small" href="/">Back to dashboard</a>
            </div>
          </div>
        ) : null}

        {state.status === "loading" && !detail ? (
          <div className="alert alert--info" role="status">Chargement du détail du flow SAML…</div>
        ) : null}

        {detail && flow ? (
          <>
            <Card title="Flow summary">
              <dl className="kv">
                <div className="kv-row">
                  <dt>Status</dt>
                  <dd>
                    <StatusBadge label={statusLabel(flow.statusBadge, flow.status)} tone={statusTone(flow.statusBadge, flow.status)} />
                  </dd>
                </div>
                <div className="kv-row">
                  <dt>Service Provider</dt>
                  <dd>
                    {sp?.name ? fmt(sp.name) : fmt(flow.runtime?.serviceProviderName || flow.serviceProviderId)}
                    {sp?.spEntityId ? <> {" — "} <code className="code">{sp.spEntityId}</code></> : null}
                  </dd>
                </div>
                <div className="kv-row">
                  <dt>Environment</dt>
                  <dd>{fmt(sp?.environmentLabel || sp?.environment || flow.environmentLabel || flow.runtime?.environmentLabel)}</dd>
                </div>
                {sp?.acsUrl ? (
                  <div className="kv-row">
                    <dt>ACS URL</dt>
                    <dd><code className="code">{fmt(sp.acsUrl)}</code></dd>
                  </div>
                ) : null}
                <div className="kv-row">
                  <dt>Started at</dt>
                  <dd>{fmt(flow.startedAt)}</dd>
                </div>
                <div className="kv-row">
                  <dt>Completed at</dt>
                  <dd>{fmt(flow.completedAt)}</dd>
                </div>
                <div className="kv-row">
                  <dt>Duration</dt>
                  <dd>{formatDuration(flow.durationMs)}</dd>
                </div>
                {flow.failedStep ? (
                  <div className="kv-row">
                    <dt>Failed step</dt>
                    <dd><code className="code">{fmt(flow.failedStep)}</code></dd>
                  </div>
                ) : null}
                {flow.errorCode ? (
                  <div className="kv-row">
                    <dt>Error code</dt>
                    <dd><code className="code">{fmt(flow.errorCode)}</code></dd>
                  </div>
                ) : null}
                {flow.errorDescription ? (
                  <div className="kv-row">
                    <dt>Error description</dt>
                    <dd>{fmt(flow.errorDescription)}</dd>
                  </div>
                ) : null}
              </dl>
            </Card>

            <TrustValidationBlock steps={detail.steps} />

            {flow.runtime ? (
              <Card
                title="Flow runtime (sanitized)"
                subtitle="RelayState is redacted, authorizationUrl is masked. Sanitization is performed by the backend."
              >
                <JsonBlock value={flow.runtime} />
              </Card>
            ) : null}

            <Card
              title="Steps"
              subtitle="Exact diagnostic values as returned by the API. Nothing is stored client-side, no clipboard interaction, no logging."
            >
              <FlowStepList steps={detail.steps} />
            </Card>
          </>
        ) : null}

      </main>
    </div>
  );
}
