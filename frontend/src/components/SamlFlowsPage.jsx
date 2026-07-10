import React, { useCallback, useEffect, useState } from "react";
import { getSamlFlows, rerunSamlFlow } from "../api/client.js";
import Card from "./Card.jsx";
import FlowActionButton from "./FlowActionButton.jsx";
import StatusBadge from "./StatusBadge.jsx";

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

export default function SamlFlowsPage() {
  const [state, setState] = useState({ status: "loading", error: "", items: [] });
  const [actionError, setActionError] = useState("");

  const load = useCallback(async () => {
    setState((previous) => ({ ...previous, status: "loading", error: "" }));
    try {
      const payload = await getSamlFlows();
      const items = Array.isArray(payload?.items) ? payload.items : [];
      setState({ status: "ready", error: "", items });
    } catch (error) {
      setState((previous) => ({
        ...previous,
        status: "error",
        error: error && error.message ? error.message : "Unknown error while fetching the API."
      }));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const isLoading = state.status === "loading";
  const items = state.items;

  return (
    <div className="page">
      <header className="topbar">
        <div className="topbar-brand">
          <span className="topbar-title">Ez-Access Debug Console</span>
          <span className="topbar-badge">Vite frontend</span>
        </div>
        <nav className="topbar-nav" aria-label="Navigation">
          <a href="/">Dashboard</a>
          <a href="/saml/service-providers">SAML SPs</a>
          <a href="/oidc/flows">OIDC flows</a>
        </nav>
      </header>

      <main className="shell">
        <section className="page-header">
          <div>
            <h1 className="page-title">SAML flows</h1>
            <p className="muted">
              Backed by <code className="code">/api/saml/flows</code>.
              Le démarrage d&apos;un flow (redirection vers l&apos;IdP puis ACS) reste géré côté backend.
            </p>
          </div>
          <div className="page-actions">
            <button type="button" className="btn" onClick={load} disabled={isLoading} aria-busy={isLoading}>
              {isLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </section>

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de récupérer les flows SAML.</strong>
            <p className="muted">{state.error}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={load}>Réessayer</button>
              <a className="btn btn--small" href="/">Back to dashboard</a>
            </div>
          </div>
        ) : null}

        {actionError ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de relancer le flow SAML.</strong>
            <p className="muted">{actionError}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={() => setActionError("")}>Fermer</button>
            </div>
          </div>
        ) : null}

        {state.status === "loading" && items.length === 0 ? (
          <div className="alert alert--info" role="status">Chargement des flows…</div>
        ) : null}

        <Card
          title={`${items.length} SAML flow${items.length === 1 ? "" : "s"} recorded`}
        >
          {items.length === 0 && state.status === "ready" ? (
            <p className="muted empty">Aucun flow SAML enregistré.</p>
          ) : (
            <ul className="list">
              {items.map((flow) => (
                <li key={flow.id} className="list-row">
                  <div className="list-main">
                    <a
                      href={`/saml/flows/${encodeURIComponent(flow.id)}`}
                      className="list-title"
                    >
                      <code className="code">{shortId(flow.id)}</code>
                    </a>
                    <div className="list-meta muted">
                      <span>{fmt(flow.serviceProviderName) || fmt(flow.serviceProviderId)}</span>
                      {flow.environmentLabel || flow.environment ? (
                        <span>· {fmt(flow.environmentLabel || flow.environment)}</span>
                      ) : null}
                    </div>
                    <div className="list-meta muted">
                      <span>started {fmt(flow.startedAt)}</span>
                      {flow.completedAt ? <span>· completed {fmt(flow.completedAt)}</span> : null}
                    </div>
                    <div className="list-meta">
                      <FlowActionButton
                        className="btn btn--small"
                        onAction={() => rerunSamlFlow(flow.id)}
                        runningLabel="Rerunning…"
                        onError={setActionError}
                        title="Relance un flow SAML pour le même Service Provider"
                      >
                        Rerun
                      </FlowActionButton>
                    </div>
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

        <footer className="footer">
          <p className="muted">
            Vue read-only. Aucun contenu SAMLResponse brut, aucune assertion,
            aucun sessionIndex n&apos;est exposé ici.
          </p>
        </footer>
      </main>
    </div>
  );
}
