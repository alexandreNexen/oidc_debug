import React from "react";
import { createSamlServiceProvider } from "../api/client.js";
import Card from "./Card.jsx";
import SamlServiceProviderForm from "./SamlServiceProviderForm.jsx";

export default function SamlServiceProviderNewPage() {
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
            <h1 className="page-title">Create SAML Service Provider</h1>
            <p className="muted">
              L&apos;ACS URL sera dérivée automatiquement de l&apos;ID généré après création.
            </p>
          </div>
        </section>

        <Card title="Service Provider details">
          <SamlServiceProviderForm
            mode="create"
            onSubmit={createSamlServiceProvider}
            submitLabel="Save SAML Service Provider"
            cancelHref="/saml/service-providers"
          />
        </Card>
      </main>
    </div>
  );
}
