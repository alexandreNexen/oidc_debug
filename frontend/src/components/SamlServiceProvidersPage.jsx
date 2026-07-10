import React, { useCallback, useEffect, useState } from "react";
import {
  deleteSamlServiceProvider,
  getSamlServiceProviders,
  startSamlFlow
} from "../api/client.js";
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

function metadataBadge(sp) {
  if (sp.idpMetadataUrl) return { tone: "success", label: "URL" };
  if (sp.idpMetadataXml) return { tone: "success", label: "XML" };
  return { tone: "warning", label: "Missing" };
}

export default function SamlServiceProvidersPage() {
  const [state, setState] = useState({ status: "loading", error: "", items: [] });
  const [actionError, setActionError] = useState("");
  const [confirmState, setConfirmState] = useState({ open: false, sp: null, busy: false, error: "" });

  const load = useCallback(async () => {
    setState((previous) => ({ ...previous, status: "loading", error: "" }));
    try {
      const payload = await getSamlServiceProviders();
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
      await deleteSamlServiceProvider(confirmState.sp.id);
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
          <a href="/oidc/service-providers">OIDC SPs</a>
          <a href="/saml/flows">SAML flows</a>
        </nav>
      </header>

      <main className="shell">
        <section className="page-header">
          <div>
            <h1 className="page-title">SAML Service Providers</h1>
            <p className="muted">
              Backed by <code className="code">/api/saml/service-providers</code>.
            </p>
          </div>
          <div className="page-actions">
            <a className="btn" href="/saml/service-providers/new">Create</a>
            <button type="button" className="btn" onClick={load} disabled={isLoading} aria-busy={isLoading}>
              {isLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </section>

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de récupérer les Service Providers SAML.</strong>
            <p className="muted">{state.error}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={load}>Réessayer</button>
            </div>
          </div>
        ) : null}

        {actionError ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de démarrer le flow SAML.</strong>
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
              Aucun Service Provider SAML configuré.{" "}
              <a href="/saml/service-providers/new">Créer un Service Provider</a>.
            </p>
          ) : (
            <ul className="list">
              {items.map((sp) => {
                const metaBadge = metadataBadge(sp);
                return (
                  <li key={sp.id} className="list-row">
                    <div className="list-main">
                      <a
                        href={`/saml/service-providers/${encodeURIComponent(sp.id)}/edit`}
                        className="list-title"
                      >
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
                      <div className="list-meta muted">
                        <span>
                          IdP metadata:{" "}
                          <span className={`badge badge--${metaBadge.tone}`}>{metaBadge.label}</span>
                        </span>
                      </div>
                      <div className="list-meta">
                        <FlowActionButton
                          className="btn btn--small"
                          onAction={() => startSamlFlow(sp.id)}
                          runningLabel="Starting…"
                          onError={setActionError}
                          title="Démarre un flow SAML et redirige vers l'IdP"
                        >
                          Start flow
                        </FlowActionButton>
                        <span className="muted"> · </span>
                        <a
                          className="btn-link"
                          href={`/saml/service-providers/${encodeURIComponent(sp.id)}/edit`}
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
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <footer className="footer">
          <p className="muted">
            Les callbacks ACS restent gérés côté backend.
          </p>
        </footer>
      </main>

      <ConfirmDialog
        open={confirmState.open}
        title="Delete SAML Service Provider"
        message={
          confirmState.sp
            ? `Delete "${confirmState.sp.name || confirmState.sp.spEntityId || confirmState.sp.id}"? This action cannot be undone.`
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
