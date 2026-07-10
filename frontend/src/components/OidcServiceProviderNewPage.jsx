import React from "react";
import { createOidcServiceProvider } from "../api/client.js";
import Card from "./Card.jsx";
import OidcServiceProviderForm from "./OidcServiceProviderForm.jsx";

export default function OidcServiceProviderNewPage() {
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
            <h1 className="page-title">Create OIDC Service Provider</h1>
            <p className="muted">
              Le client_secret est transmis uniquement par POST same-origin, chiffré
              côté serveur, puis oublié — jamais renvoyé par l&apos;API.
            </p>
          </div>
        </section>

        <Card title="Service Provider details">
          <OidcServiceProviderForm
            mode="create"
            onSubmit={createOidcServiceProvider}
            submitLabel="Save Service Provider"
            cancelHref="/oidc/service-providers"
          />
        </Card>
      </main>
    </div>
  );
}
