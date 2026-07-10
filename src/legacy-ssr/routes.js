import path from "node:path";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { listEzAccessEnvironments } from "../common/config.js";
import { renderDashboard } from "./views/common/dashboard.js";
import { renderServiceProvidersPage } from "./views/oidc/serviceProviders.js";
import { renderServiceProviderNewPage } from "./views/oidc/serviceProviderNew.js";
import { renderServiceProviderEditPage } from "./views/oidc/serviceProviderEdit.js";
import { renderFlowResultPage } from "./views/oidc/flowResult.js";
import { renderFlowDetailsPage } from "./views/oidc/flowDetails.js";
import { renderSamlServiceProvidersPage } from "./views/saml/serviceProviders.js";
import { renderSamlServiceProviderNewPage } from "./views/saml/serviceProviderNew.js";
import { renderSamlServiceProviderEditPage } from "./views/saml/serviceProviderEdit.js";
import { renderSamlFlowResultPage } from "./views/saml/flowResult.js";
import { renderSamlFlowDetailsPage } from "./views/saml/flowDetails.js";

// Legacy SSR is a flag-only read-only reference of the pre-Vite UI. All
// write actions (create/update/delete Service Providers, discovery import,
// flow start) go through /api/* or the canonical backend routes. This
// router is mounted under /legacy/* by server.js, and ONLY when
// ENABLE_LEGACY_SSR=1. NODE_ENV alone no longer activates it — dev and
// prod behave identically without the flag.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LEGACY_ASSETS_DIR = path.join(__dirname, "assets");

const ASSET_MIME = new Map([
  [".css", "text/css; charset=utf-8"],
  [".js", "application/javascript; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".ico", "image/x-icon"],
  [".png", "image/png"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"]
]);

function assetMimeType(filePath) {
  return ASSET_MIME.get(path.extname(filePath).toLowerCase()) || "application/octet-stream";
}

export function isLegacySsrEnabled(env = process.env) {
  return env.ENABLE_LEGACY_SSR === "1";
}

export function createLegacyRouter(deps) {
  const {
    getOrCreateSession,
    buildPageModel,
    buildFlowViewModel,
    buildSamlFlowViewModel,
    getServiceProvider,
    sanitizeServiceProviderForUi,
    sanitizeSamlServiceProviderForUi,
    attachSamlFlowsToServiceProviders,
    sanitizeEzAccessEnvironmentForUi,
    consumeFlash,
    setFlash,
    redirect,
    sendHtml,
    sendJson,
    send,
    samlServiceProviderService
  } = deps;

  async function serveLegacyAsset(res, subpath) {
    if (!subpath || subpath.length > 256) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }
    if (subpath.startsWith("/") || subpath.includes("..") || !/^[A-Za-z0-9._/-]+$/.test(subpath)) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }
    const resolved = path.resolve(LEGACY_ASSETS_DIR, subpath);
    const prefix = LEGACY_ASSETS_DIR + path.sep;
    if (!resolved.startsWith(prefix)) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }
    try {
      const content = await readFile(resolved);
      send(res, 200, content, assetMimeType(resolved));
    } catch {
      sendJson(res, 404, { error: "Legacy asset not found." });
    }
  }

  async function handleLegacyRoute(req, res, url) {
    if (url.pathname !== "/legacy" && !url.pathname.startsWith("/legacy/")) {
      return false;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      sendJson(res, 405, { error: "Legacy SSR is read-only." });
      return true;
    }

    if (url.pathname.startsWith("/legacy/assets/")) {
      await serveLegacyAsset(res, url.pathname.slice("/legacy/assets/".length));
      return true;
    }

    if (url.pathname === "/legacy" || url.pathname === "/legacy/") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "dashboard", url);
      sendHtml(res, renderDashboard(model));
      return true;
    }

    if (url.pathname === "/legacy/oidc/service-providers") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "service-providers", url);
      sendHtml(res, renderServiceProvidersPage(model));
      return true;
    }

    if (url.pathname === "/legacy/oidc/service-providers/new") {
      const session = getOrCreateSession(req, res);
      const model = buildPageModel(session, "service-providers", url);
      sendHtml(res, renderServiceProviderNewPage(model));
      return true;
    }

    const oidcEditMatch = url.pathname.match(/^\/legacy\/oidc\/service-providers\/([^/]+)\/edit$/);
    if (oidcEditMatch) {
      const spId = decodeURIComponent(oidcEditMatch[1]);
      const session = getOrCreateSession(req, res);
      const serviceProvider = getServiceProvider(spId);
      if (!serviceProvider) {
        setFlash(session, "warn", "Service Provider not found.");
        redirect(res, "/legacy/oidc/service-providers");
        return true;
      }
      const model = {
        ...buildPageModel(session, "service-providers", url),
        serviceProvider: sanitizeServiceProviderForUi(serviceProvider)
      };
      sendHtml(res, renderServiceProviderEditPage(model));
      return true;
    }

    const oidcDetailsMatch = url.pathname.match(/^\/legacy\/oidc\/flows\/([^/]+)\/details$/);
    if (oidcDetailsMatch) {
      const flowId = decodeURIComponent(oidcDetailsMatch[1]);
      const session = getOrCreateSession(req, res);
      const model = buildFlowViewModel(session, flowId, url);
      if (!model) {
        setFlash(session, "warn", "Flow not found.");
        redirect(res, "/legacy/oidc/service-providers");
        return true;
      }
      sendHtml(res, renderFlowDetailsPage(model));
      return true;
    }

    const oidcResultMatch = url.pathname.match(/^\/legacy\/oidc\/flows\/([^/]+)$/);
    if (oidcResultMatch) {
      const flowId = decodeURIComponent(oidcResultMatch[1]);
      const session = getOrCreateSession(req, res);
      const model = buildFlowViewModel(session, flowId, url);
      if (!model) {
        setFlash(session, "warn", "Flow not found.");
        redirect(res, "/legacy/oidc/service-providers");
        return true;
      }
      sendHtml(res, renderFlowResultPage(model));
      return true;
    }

    if (url.pathname === "/legacy/saml/service-providers") {
      const session = getOrCreateSession(req, res);
      const flash = consumeFlash(session);
      const model = {
        serviceProviders: attachSamlFlowsToServiceProviders(
          samlServiceProviderService.listSamlServiceProviders().map(sanitizeSamlServiceProviderForUi)
        ),
        flash
      };
      sendHtml(res, renderSamlServiceProvidersPage(model));
      return true;
    }

    if (url.pathname === "/legacy/saml/service-providers/new") {
      const session = getOrCreateSession(req, res);
      sendHtml(res, renderSamlServiceProviderNewPage({
        flash: consumeFlash(session),
        ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi)
      }));
      return true;
    }

    const samlEditMatch = url.pathname.match(/^\/legacy\/saml\/service-providers\/([^/]+)\/edit$/);
    if (samlEditMatch) {
      const spId = decodeURIComponent(samlEditMatch[1]);
      const session = getOrCreateSession(req, res);
      const sp = samlServiceProviderService.getSamlServiceProvider(spId);
      if (!sp) {
        setFlash(session, "warn", "SAML Service Provider not found.");
        redirect(res, "/legacy/saml/service-providers");
        return true;
      }
      const sanitizedSp = sanitizeSamlServiceProviderForUi(sp);
      sendHtml(res, renderSamlServiceProviderEditPage({
        serviceProvider: sanitizedSp,
        flash: consumeFlash(session),
        ezAccessEnvironments: listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi),
        acsUrl: sanitizedSp.acsUrl
      }));
      return true;
    }

    const samlDetailsMatch = url.pathname.match(/^\/legacy\/saml\/flows\/([^/]+)\/details$/);
    if (samlDetailsMatch) {
      const flowId = decodeURIComponent(samlDetailsMatch[1]);
      const session = getOrCreateSession(req, res);
      const model = buildSamlFlowViewModel(session, flowId, url);
      if (!model) {
        setFlash(session, "warn", "SAML flow not found.");
        redirect(res, "/legacy/saml/service-providers");
        return true;
      }
      sendHtml(res, renderSamlFlowDetailsPage(model));
      return true;
    }

    const samlResultMatch = url.pathname.match(/^\/legacy\/saml\/flows\/([^/]+)$/);
    if (samlResultMatch) {
      const flowId = decodeURIComponent(samlResultMatch[1]);
      const session = getOrCreateSession(req, res);
      const model = buildSamlFlowViewModel(session, flowId, url);
      if (!model) {
        setFlash(session, "warn", "SAML flow not found.");
        redirect(res, "/legacy/saml/service-providers");
        return true;
      }
      sendHtml(res, renderSamlFlowResultPage(model));
      return true;
    }

    sendJson(res, 404, { error: "Legacy route not found." });
    return true;
  }

  return { handleLegacyRoute };
}
