import React, { useCallback, useEffect, useState } from "react";
import {
  deleteOidcServiceProvider,
  getOidcServiceProvider,
  updateOidcServiceProvider
} from "../api/client.js";
import Card from "./Card.jsx";
import ConfirmDialog from "./ConfirmDialog.jsx";
import OidcServiceProviderForm from "./OidcServiceProviderForm.jsx";

export default function OidcServiceProviderEditPage({ spId }) {
  const [state, setState] = useState({
    status: "loading",
    error: "",
    errorStatus: 0,
    serviceProvider: null
  });
  const [confirmState, setConfirmState] = useState({ open: false, busy: false, error: "" });

  const load = useCallback(async () => {
    setState({ status: "loading", error: "", errorStatus: 0, serviceProvider: null });
    try {
      const payload = await getOidcServiceProvider(spId);
      setState({
        status: "ready",
        error: "",
        errorStatus: 0,
        serviceProvider: payload?.serviceProvider || null
      });
    } catch (error) {
      const message = error && error.message ? error.message : "Impossible de charger le Service Provider.";
      const errorStatus = error && typeof error.status === "number" ? error.status : 0;
      setState({ status: "error", error: message, errorStatus, serviceProvider: null });
    }
  }, [spId]);

  useEffect(() => {
    load();
  }, [load]);

  const sp = state.serviceProvider;

  const handleSubmit = useCallback(
    (payload) => updateOidcServiceProvider(spId, payload),
    [spId]
  );

  const requestDelete = useCallback(() => {
    setConfirmState({ open: true, busy: false, error: "" });
  }, []);

  const cancelDelete = useCallback(() => {
    setConfirmState({ open: false, busy: false, error: "" });
  }, []);

  const confirmDelete = useCallback(async () => {
    setConfirmState((prev) => ({ ...prev, busy: true, error: "" }));
    try {
      const response = await deleteOidcServiceProvider(spId);
      const redirectUrl =
        response && typeof response.redirectUrl === "string"
          ? response.redirectUrl
          : "/oidc/service-providers";
      window.location.assign(redirectUrl);
    } catch (error) {
      const message = error && error.message ? error.message : "Delete failed.";
      setConfirmState((prev) => ({ ...prev, busy: false, error: message }));
    }
  }, [spId]);

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
            <h1 className="page-title">Edit OIDC Service Provider</h1>
            <p className="muted">
              Le secret existant n&apos;est jamais renvoyé par l&apos;API. Laissez le champ
              vide pour le conserver, ou saisissez une nouvelle valeur pour le remplacer.
            </p>
          </div>
        </section>

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>
              {state.errorStatus === 404
                ? "Service Provider introuvable."
                : "Impossible de charger le Service Provider."}
            </strong>
            <p className="muted">{state.error}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={load}>
                Réessayer
              </button>
              <a className="btn btn--small" href="/oidc/service-providers">
                Back to list
              </a>
            </div>
          </div>
        ) : null}

        {state.status === "loading" && !sp ? (
          <div className="alert alert--info" role="status">
            Chargement du Service Provider…
          </div>
        ) : null}

        {sp ? (
          <>
            <Card
              title="Service Provider details"
              subtitle={`ID: ${sp.id}`}
            >
              <OidcServiceProviderForm
                mode="edit"
                initial={{
                  name: sp.name || "",
                  clientId: sp.clientId || "",
                  scopes: sp.scopes || "",
                  environment: sp.environment || ""
                }}
                secretConfigured={Boolean(sp.secretConfigured)}
                onSubmit={handleSubmit}
                submitLabel="Save changes"
                cancelHref="/oidc/service-providers"
              />
            </Card>

            <Card
              title="Danger zone"
              subtitle="Cette action est irréversible. Les flows historiques référençant ce SP sont conservés à des fins de diagnostic."
            >
              <div className="page-actions">
                <button type="button" className="btn btn--danger" onClick={requestDelete}>
                  Delete Service Provider
                </button>
              </div>
            </Card>
          </>
        ) : null}

      </main>

      <ConfirmDialog
        open={confirmState.open}
        title="Delete OIDC Service Provider"
        message={
          sp
            ? `Delete "${sp.name || sp.clientId || sp.id}"? This action cannot be undone.`
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
