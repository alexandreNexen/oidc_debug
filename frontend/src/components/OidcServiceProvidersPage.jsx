import React, { useCallback, useEffect, useState } from "react";
import { deleteOidcServiceProvider, getOidcServiceProviders, startOidcFlow } from "../api/client.js";
import Card from "./Card.jsx";
import ConfirmDialog from "./ConfirmDialog.jsx";
import FlowActionButton from "./FlowActionButton.jsx";
import StatusBadge from "./StatusBadge.jsx";

function fmt(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function statusTone(status) {
  if (status && typeof status === "object" && typeof status.tone === "string") return status.tone;
  if (status === "ready") return "success";
  if (status === "incomplete") return "warning";
  if (status === "invalid") return "error";
  return "neutral";
}

function statusLabel(status) {
  if (status && typeof status === "object" && typeof status.label === "string" && status.label) return status.label;
  if (typeof status === "string" && status) return status;
  return "—";
}

function renderScopes(scopes) {
  const raw = typeof scopes === "string" ? scopes : "";
  const tokens = raw.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return <span className="muted">Missing</span>;
  }
  return (
    <span className="scope-list">
      {tokens.map((scope) => (
        <span key={scope} className="badge badge--neutral">{scope}</span>
      ))}
    </span>
  );
}

export default function OidcServiceProvidersPage() {
  const [state, setState] = useState({ status: "loading", error: "", items: [] });
  const [actionError, setActionError] = useState("");
  const [confirmState, setConfirmState] = useState({ open: false, sp: null, busy: false, error: "" });

  const load = useCallback(async () => {
    setState((previous) => ({ ...previous, status: "loading", error: "" }));
    try {
      const payload = await getOidcServiceProviders();
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

  const requestDelete = useCallback((sp) => {
    setConfirmState({ open: true, sp, busy: false, error: "" });
  }, []);

  const cancelDelete = useCallback(() => {
    setConfirmState({ open: false, sp: null, busy: false, error: "" });
  }, []);

  const confirmDelete = useCallback(async () => {
    setConfirmState((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      await deleteOidcServiceProvider(confirmState.sp.id);
      setConfirmState({ open: false, sp: null, busy: false, error: "" });
      load();
    } catch (error) {
      const message = error && error.message ? error.message : "Delete failed.";
      setConfirmState((prev) => ({ ...prev, busy: false, error: message }));
    }
  }, [confirmState.sp, load]);

  const isLoading = state.status === "loading";
  const items = state.items;

  return (
    <div className="page">
      <header className="topbar">
        <div className="topbar-brand">
          <span className="topbar-title">Ez-Access Debug Console</span>
          <span className="topbar-badge">Vite frontend · read-only</span>
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
            <h1 className="page-title">OIDC Service Providers</h1>
            <p className="muted">
              Backed by <code className="code">/api/oidc/service-providers</code>.
            </p>
          </div>
          <div className="page-actions">
            <a className="btn" href="/oidc/service-providers/new">Create</a>
            <button type="button" className="btn" onClick={load} disabled={isLoading} aria-busy={isLoading}>
              {isLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </section>

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de récupérer les Service Providers OIDC.</strong>
            <p className="muted">{state.error}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={load}>Réessayer</button>
            </div>
          </div>
        ) : null}

        {actionError ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de démarrer le flow.</strong>
            <p className="muted">{actionError}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={() => setActionError("")}>Fermer</button>
            </div>
          </div>
        ) : null}

        {state.status === "loading" && items.length === 0 ? (
          <div className="alert alert--info" role="status">Chargement des Service Providers…</div>
        ) : null}

        <Card
          title={`${items.length} Service Provider${items.length === 1 ? "" : "s"} configured`}
        >
          {items.length === 0 && state.status === "ready" ? (
            <p className="muted empty">
              Aucun Service Provider OIDC configuré.{" "}
              <a href="/oidc/service-providers/new">Créer un Service Provider</a>.
            </p>
          ) : (
            <ul className="list">
              {items.map((sp) => (
                <li key={sp.id} className="list-row">
                  <div className="list-main">
                    <a
                      href={`/oidc/service-providers/${encodeURIComponent(sp.id)}/edit`}
                      className="list-title"
                    >
                      {fmt(sp.name) || fmt(sp.clientId) || fmt(sp.id)}
                    </a>
                    <div className="list-meta muted">
                      <code className="code">{fmt(sp.clientId)}</code>
                      <span>· {fmt(sp.clientType)}</span>
                      <span>· {fmt(sp.environmentLabel || sp.environment)}</span>
                    </div>
                    <div className="list-meta">{renderScopes(sp.scopes)}</div>
                    <div className="list-meta">
                      <FlowActionButton
                        className="btn btn--small"
                        onAction={() => startOidcFlow(sp.id)}
                        runningLabel="Starting…"
                        onError={setActionError}
                        title="Démarre un flow OIDC pour ce Service Provider et redirige vers l'IdP"
                      >
                        Start flow
                      </FlowActionButton>
                      <span className="muted"> · </span>
                      <a
                        className="btn-link"
                        href={`/oidc/service-providers/${encodeURIComponent(sp.id)}/edit`}
                      >
                        Edit
                      </a>
                      <span className="muted"> · </span>
                      <button
                        type="button"
                        className="btn-link btn-link--danger"
                        onClick={() => requestDelete(sp)}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                  <div className="list-side">
                    <StatusBadge label={statusLabel(sp.status)} tone={statusTone(sp.status)} />
                    <span className={`badge badge--${sp.secretConfigured ? "success" : "warning"}`}>
                      {sp.secretConfigured ? "secret configured" : "no secret"}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

      </main>

      <ConfirmDialog
        open={confirmState.open}
        title="Delete OIDC Service Provider"
        message={
          confirmState.sp
            ? `Delete "${confirmState.sp.name || confirmState.sp.clientId || confirmState.sp.id}"? This action cannot be undone.`
            : ""
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        busy={confirmState.busy}
        error={confirmState.error}
        danger
        onConfirm={confirmDelete}
        onCancel={cancelDelete}
      />
    </div>
  );
}
