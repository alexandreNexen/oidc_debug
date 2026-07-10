import React, { useEffect, useState } from "react";
import Dashboard from "./components/Dashboard.jsx";
import OidcFlowDetailPage from "./components/OidcFlowDetailPage.jsx";
import SamlFlowDetailPage from "./components/SamlFlowDetailPage.jsx";
import OidcServiceProvidersPage from "./components/OidcServiceProvidersPage.jsx";
import OidcServiceProviderNewPage from "./components/OidcServiceProviderNewPage.jsx";
import OidcServiceProviderEditPage from "./components/OidcServiceProviderEditPage.jsx";
import SamlServiceProvidersPage from "./components/SamlServiceProvidersPage.jsx";
import SamlServiceProviderNewPage from "./components/SamlServiceProviderNewPage.jsx";
import SamlServiceProviderEditPage from "./components/SamlServiceProviderEditPage.jsx";
import OidcFlowsPage from "./components/OidcFlowsPage.jsx";
import SamlFlowsPage from "./components/SamlFlowsPage.jsx";

// Minimal SPA router.
// Canonical (clean) routes served by the SPA (allow-list, matched server-side):
// - `/`                                     -> Dashboard
// - `/oidc/service-providers`               -> OidcServiceProvidersPage
// - `/oidc/service-providers/new`           -> OidcServiceProviderNewPage
// - `/oidc/service-providers/:id/edit`      -> OidcServiceProviderEditPage
// - `/oidc/flows`                           -> OidcFlowsPage
// - `/oidc/flows/:id`                       -> OidcFlowDetailPage
// - `/saml/service-providers`               -> SamlServiceProvidersPage
// - `/saml/service-providers/new`           -> SamlServiceProviderNewPage
// - `/saml/service-providers/:id/edit`      -> SamlServiceProviderEditPage
// - `/saml/flows`                           -> SamlFlowsPage
// - `/saml/flows/:id`                       -> SamlFlowDetailPage
//
// The `/vite/` prefix is preserved as a temporary alias (backward compatibility
// with older bookmarks and integration tests). Callbacks (`/oidc/callback`,
// `/saml/acs/:spId`) and flow start endpoints are handled by the backend and
// intentionally not part of this allow-list.
function stripVitePrefix(pathname) {
  if (pathname === "/vite" || pathname === "/vite/") return "/";
  if (pathname.startsWith("/vite/")) return pathname.slice("/vite".length);
  return pathname;
}

function parseRoute(rawPathname) {
  const pathname = stripVitePrefix(rawPathname);

  const oidcFlowMatch = pathname.match(/^\/oidc\/flows\/([^/]+)\/?$/);
  if (oidcFlowMatch) {
    return { name: "oidcFlowDetail", flowId: decodeURIComponent(oidcFlowMatch[1]) };
  }
  const samlFlowMatch = pathname.match(/^\/saml\/flows\/([^/]+)\/?$/);
  if (samlFlowMatch) {
    return { name: "samlFlowDetail", flowId: decodeURIComponent(samlFlowMatch[1]) };
  }
  if (/^\/oidc\/service-providers\/new\/?$/.test(pathname)) {
    return { name: "oidcServiceProviderNew" };
  }
  const oidcSpEditMatch = pathname.match(/^\/oidc\/service-providers\/([^/]+)\/edit\/?$/);
  if (oidcSpEditMatch) {
    return { name: "oidcServiceProviderEdit", spId: decodeURIComponent(oidcSpEditMatch[1]) };
  }
  if (/^\/oidc\/service-providers\/?$/.test(pathname)) {
    return { name: "oidcServiceProviders" };
  }
  if (/^\/saml\/service-providers\/new\/?$/.test(pathname)) {
    return { name: "samlServiceProviderNew" };
  }
  const samlSpEditMatch = pathname.match(/^\/saml\/service-providers\/([^/]+)\/edit\/?$/);
  if (samlSpEditMatch) {
    return { name: "samlServiceProviderEdit", spId: decodeURIComponent(samlSpEditMatch[1]) };
  }
  if (/^\/saml\/service-providers\/?$/.test(pathname)) {
    return { name: "samlServiceProviders" };
  }
  if (/^\/oidc\/flows\/?$/.test(pathname)) {
    return { name: "oidcFlows" };
  }
  if (/^\/saml\/flows\/?$/.test(pathname)) {
    return { name: "samlFlows" };
  }
  return { name: "dashboard" };
}

export default function App() {
  const [route, setRoute] = useState(() => parseRoute(window.location.pathname));

  useEffect(() => {
    const onPopState = () => setRoute(parseRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  if (route.name === "oidcFlowDetail") {
    return <OidcFlowDetailPage flowId={route.flowId} />;
  }
  if (route.name === "samlFlowDetail") {
    return <SamlFlowDetailPage flowId={route.flowId} />;
  }
  if (route.name === "oidcServiceProviders") {
    return <OidcServiceProvidersPage />;
  }
  if (route.name === "oidcServiceProviderNew") {
    return <OidcServiceProviderNewPage />;
  }
  if (route.name === "oidcServiceProviderEdit") {
    return <OidcServiceProviderEditPage spId={route.spId} />;
  }
  if (route.name === "samlServiceProviders") {
    return <SamlServiceProvidersPage />;
  }
  if (route.name === "samlServiceProviderNew") {
    return <SamlServiceProviderNewPage />;
  }
  if (route.name === "samlServiceProviderEdit") {
    return <SamlServiceProviderEditPage spId={route.spId} />;
  }
  if (route.name === "oidcFlows") {
    return <OidcFlowsPage />;
  }
  if (route.name === "samlFlows") {
    return <SamlFlowsPage />;
  }
  return <Dashboard />;
}
