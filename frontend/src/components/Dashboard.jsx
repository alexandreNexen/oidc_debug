import React, { useCallback, useEffect, useState } from "react";
import {
  getHealth,
  getOidcFlows,
  getOidcServiceProviders,
  getSamlFlows,
  getSamlServiceProviders
} from "../api/client.js";
import HealthPanel from "./HealthPanel.jsx";
import ServiceProvidersPanel from "./ServiceProvidersPanel.jsx";
import FlowsPanel from "./FlowsPanel.jsx";

const INITIAL_STATE = {
  status: "idle",
  error: "",
  fetchedAt: "",
  health: null,
  oidcServiceProviders: null,
  oidcFlows: null,
  samlServiceProviders: null,
  samlFlows: null
};

function itemsOf(payload) {
  if (!payload || typeof payload !== "object") return [];
  return Array.isArray(payload.items) ? payload.items : [];
}

export default function Dashboard() {
  const [state, setState] = useState(INITIAL_STATE);

  const load = useCallback(async () => {
    setState((previous) => ({ ...previous, status: "loading", error: "" }));
    try {
      const [health, oidcSps, oidcFlows, samlSps, samlFlows] = await Promise.all([
        getHealth(),
        getOidcServiceProviders(),
        getOidcFlows(),
        getSamlServiceProviders(),
        getSamlFlows()
      ]);

      setState({
        status: "ready",
        error: "",
        fetchedAt: new Date().toISOString(),
        health,
        oidcServiceProviders: itemsOf(oidcSps),
        oidcFlows: itemsOf(oidcFlows),
        samlServiceProviders: itemsOf(samlSps),
        samlFlows: itemsOf(samlFlows)
      });
    } catch (error) {
      setState((previous) => ({
        ...previous,
        status: "error",
        error: error && error.message ? error.message : "Unknown error while fetching backend data."
      }));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const isLoading = state.status === "loading";

  return (
    <div className="page">
      <header className="topbar">
        <div className="topbar-brand">
          <span className="topbar-title">Ez-Access Debug Console</span>
          <span className="topbar-badge">Vite frontend</span>
        </div>
        <nav className="topbar-nav" aria-label="Navigation">
          <a href="/oidc/service-providers">OIDC SPs</a>
          <a href="/saml/service-providers">SAML SPs</a>
          <a href="/oidc/flows">OIDC flows</a>
          <a href="/saml/flows">SAML flows</a>
          <a href="/health">/health</a>
        </nav>
      </header>

      <main className="shell">
        <section className="page-header">
          <div>
            <h1 className="page-title">Dashboard</h1>
            <p className="muted">
              Vue de synthèse alimentée par <code className="code">/api/*</code>.
            </p>
          </div>
          <div className="page-actions">
            <button
              type="button"
              className="btn"
              onClick={load}
              disabled={isLoading}
              aria-busy={isLoading}
            >
              {isLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </section>

        {state.status === "error" ? (
          <div className="alert alert--error" role="alert">
            <strong>Impossible de récupérer les données de l&apos;API.</strong>
            <p className="muted">{state.error || "Erreur inconnue."}</p>
            <button type="button" className="btn btn--small" onClick={load}>
              Réessayer
            </button>
          </div>
        ) : null}

        {state.status === "loading" && !state.health ? (
          <div className="alert alert--info" role="status">
            Chargement des données de synthèse…
          </div>
        ) : null}

        {state.health ? (
          <HealthPanel health={state.health} fetchedAt={state.fetchedAt} />
        ) : null}

        <div className="grid">
          <ServiceProvidersPanel protocol="OIDC" items={state.oidcServiceProviders} />
          <ServiceProvidersPanel protocol="SAML" items={state.samlServiceProviders} />
          <FlowsPanel protocol="OIDC" items={state.oidcFlows} />
          <FlowsPanel protocol="SAML" items={state.samlFlows} />
        </div>

      </main>
    </div>
  );
}
