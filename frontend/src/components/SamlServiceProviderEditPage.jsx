import React, { useCallback, useEffect, useState } from "react";
import {
  deleteSamlServiceProvider,
  getSamlServiceProvider,
  updateSamlServiceProvider
} from "../api/client.js";
import Card from "./Card.jsx";
import ConfirmDialog from "./ConfirmDialog.jsx";
import SamlServiceProviderForm from "./SamlServiceProviderForm.jsx";

export default function SamlServiceProviderEditPage({ spId }) {
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
      const payload = await getSamlServiceProvider(spId);
      setState({
        status: "ready",
        error: "",
        errorStatus: 0,
        serviceProvider: payload?.serviceProvider || null
      });
    } catch (error) {
      const message =
        error && error.message ? error.message : "Impossible de charger le Service Provider SAML.";
      const errorStatus = error && typeof error.status === "number" ? error.status : 0;
      setState({ status: "error", error: message, errorStatus, serviceProvider: null });
    }
  }, [spId]);

  useEffect(() => {
    load();
  }, [load]);

  const sp = state.serviceProvider;

  const handleSubmit = useCallback(
    (payload) => updateSamlServiceProvider(spId, payload),
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
      const response = await deleteSamlServiceProvider(spId);
      const redirectUrl =
        response && typeof response.redirectUrl === "string"
          ? response.redirectUrl
          : "/saml/service-providers";
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
            <h1 className="page-title">Edit SAML Service Provider</h1>
            <p className="muted">
              Modifier les métadonnées de connexion à l&apos;IdP. La validation SAML,
              la vérification de signature et l&apos;ACS restent gérées côté backend.
            </p>
          </div>
        </section>

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>
              {state.errorStatus === 404
                ? "SAML Service Provider introuvable."
                : "Impossible de charger le Service Provider SAML."}
            </strong>
            <p className="muted">{state.error}</p>
            <div className="page-actions">
              <button type="button" className="btn btn--small" onClick={load}>
                Réessayer
              </button>
              <a className="btn btn--small" href="/saml/service-providers">
                Back to list
              </a>
            </div>
          </div>
        ) : null}

        {state.status === "loading" && !sp ? (
          <div className="alert alert--info" role="status">
            Chargement du Service Provider SAML…
          </div>
        ) : null}

        {sp ? (
          <>
            <Card title="Service Provider details" subtitle={`ID: ${sp.id}`}>
              <SamlServiceProviderForm
                mode="edit"
                initial={{
                  name: sp.name || "",
                  environment: sp.environment || "",
                  spEntityId: sp.spEntityId || "",
                  idpMetadataUrl: sp.idpMetadataUrl || "",
                  idpMetadataXml: sp.idpMetadataXml || "",
                  idpMetadataMode:
                    sp.idpMetadataXml && !sp.idpMetadataUrl ? "xml" : "url"
                }}
                acsUrl={sp.acsUrl || ""}
                onSubmit={handleSubmit}
                submitLabel="Save changes"
                cancelHref="/saml/service-providers"
              />
            </Card>

            <Card
              title="Danger zone"
              subtitle="Cette action est irréversible. Les flows historiques référençant ce SP sont conservés à des fins de diagnostic."
            >
              <div className="page-actions">
                <button type="button" className="btn btn--danger" onClick={requestDelete}>
                  Delete SAML Service Provider
                </button>
              </div>
            </Card>
          </>
        ) : null}

      </main>

      <ConfirmDialog
        open={confirmState.open}
        title="Delete SAML Service Provider"
        message={
          sp
            ? `Delete "${sp.name || sp.spEntityId || sp.id}"? This action cannot be undone.`
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
