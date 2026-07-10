// SAML JSON API endpoints served under /api/saml/*. Extracted verbatim
// from the pre-refactor server.js inline block — identical URLs, methods,
// status codes, payloads, rate-limit budgets and error messages. All
// dependencies are injected through the factory so this module has no
// hidden global state.
//
// Endpoints handled here:
//   GET    /api/saml/service-providers
//   GET    /api/saml/service-providers/:spId
//   POST   /api/saml/service-providers
//   PATCH  /api/saml/service-providers/:spId
//   DELETE /api/saml/service-providers/:spId
//   GET    /api/saml/flows
//   GET    /api/saml/flows/:flowId
//   POST   /api/saml/flows/start/:spId
//   POST   /api/saml/flows/:flowId/rerun
//
// The cross-site guard (`assertApiPostAllowed`) is applied ONCE by the
// root API router (see routes/api/index.js) before delegation, so nothing
// here has to repeat it.

export function createSamlApiRouter({ http, security, sessions, saml }) {
  const { sendJson, readBody, parseBody } = http;
  const { checkRateLimit } = security;
  const { getOrCreateSession, addSessionLog } = sessions;
  const {
    samlServiceProviderService,
    samlFlowService,
    sanitizeSamlServiceProviderForUi,
    samlFlowSummary,
    buildApiSamlFlowDetail,
    startNewSamlUiFlow
  } = saml;

  async function handle(req, res, url) {
    if (!url.pathname.startsWith("/api/saml/")) return false;

    if (req.method === "GET" && url.pathname === "/api/saml/service-providers") {
      const items = samlServiceProviderService.listSamlServiceProviders().map(sanitizeSamlServiceProviderForUi);
      sendJson(res, 200, { items });
      return true;
    }

    // ---- SAML Service Provider write endpoints ----
    // Delegate to `samlServiceProviderService` so validation, storage, and
    // metadata-mode inference (URL vs XML) go through the same code path
    // as SSR. `sanitizeSamlServiceProviderForUi` strips nothing sensitive
    // (the persisted model has no keys or secrets) but does add the
    // derived `acsUrl` for the UI. The delete handler mirrors the SSR
    // one; historical SAML flows referencing the SP are kept intact.

    const apiSamlSpDetailMatch = req.method === "GET"
      ? url.pathname.match(/^\/api\/saml\/service-providers\/([^/]+)$/)
      : null;
    if (apiSamlSpDetailMatch) {
      const spId = decodeURIComponent(apiSamlSpDetailMatch[1]);
      const sp = samlServiceProviderService.getSamlServiceProvider(spId);
      if (!sp) {
        sendJson(res, 404, { error: "SAML Service Provider not found." });
        return true;
      }
      sendJson(res, 200, { serviceProvider: sanitizeSamlServiceProviderForUi(sp) });
      return true;
    }

    if (req.method === "POST" && url.pathname === "/api/saml/service-providers") {
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "saml-sp-create", 20, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return true;
      }
      let body;
      try {
        const rawBody = await readBody(req);
        body = parseBody(req, rawBody);
      } catch (error) {
        if (error && error.code === "BODY_TOO_LARGE") {
          sendJson(res, 413, { error: "Request body exceeds size limit." });
          return true;
        }
        throw error;
      }
      const result = samlServiceProviderService.createSamlServiceProvider(body);
      if (!result.ok) {
        sendJson(res, 400, {
          error: "Please fix the highlighted fields.",
          fieldErrors: result.validation.errors,
          warnings: result.validation.warnings
        });
        return true;
      }
      addSessionLog(session, "info", "saml_sp_created", "SAML Service Provider created.", {
        serviceProviderId: result.serviceProvider.id,
        name: result.serviceProvider.name
      });
      sendJson(res, 200, {
        id: result.serviceProvider.id,
        redirectUrl: "/saml/service-providers",
        warnings: result.validation.warnings
      });
      return true;
    }

    const apiSamlSpUpdateMatch = req.method === "PATCH"
      ? url.pathname.match(/^\/api\/saml\/service-providers\/([^/]+)$/)
      : null;
    if (apiSamlSpUpdateMatch) {
      const spId = decodeURIComponent(apiSamlSpUpdateMatch[1]);
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "saml-sp-create", 20, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return true;
      }
      let body;
      try {
        const rawBody = await readBody(req);
        body = parseBody(req, rawBody);
      } catch (error) {
        if (error && error.code === "BODY_TOO_LARGE") {
          sendJson(res, 413, { error: "Request body exceeds size limit." });
          return true;
        }
        throw error;
      }
      const result = samlServiceProviderService.updateSamlServiceProvider(spId, body);
      if (result.notFound) {
        sendJson(res, 404, { error: "SAML Service Provider not found." });
        return true;
      }
      if (!result.ok) {
        sendJson(res, 400, {
          error: "Please fix the highlighted fields.",
          fieldErrors: result.validation.errors,
          warnings: result.validation.warnings
        });
        return true;
      }
      addSessionLog(session, "info", "saml_sp_updated", "SAML Service Provider updated.", {
        serviceProviderId: result.serviceProvider.id,
        name: result.serviceProvider.name
      });
      sendJson(res, 200, {
        id: result.serviceProvider.id,
        redirectUrl: "/saml/service-providers",
        warnings: result.validation.warnings
      });
      return true;
    }

    const apiSamlSpDeleteMatch = req.method === "DELETE"
      ? url.pathname.match(/^\/api\/saml\/service-providers\/([^/]+)$/)
      : null;
    if (apiSamlSpDeleteMatch) {
      const spId = decodeURIComponent(apiSamlSpDeleteMatch[1]);
      const session = getOrCreateSession(req, res);
      if (!samlServiceProviderService.deleteSamlServiceProvider(spId)) {
        sendJson(res, 404, { error: "SAML Service Provider not found." });
        return true;
      }
      addSessionLog(session, "info", "saml_sp_deleted", "SAML Service Provider deleted.", {
        serviceProviderId: spId
      });
      sendJson(res, 200, {
        deleted: true,
        id: spId,
        redirectUrl: "/saml/service-providers"
      });
      return true;
    }

    if (req.method === "GET" && url.pathname === "/api/saml/flows") {
      const items = samlFlowService.listFlows().map(samlFlowSummary);
      sendJson(res, 200, { items });
      return true;
    }

    const apiSamlFlowMatch = req.method === "GET" ? url.pathname.match(/^\/api\/saml\/flows\/([^/]+)$/) : null;
    if (apiSamlFlowMatch) {
      const flowId = decodeURIComponent(apiSamlFlowMatch[1]);
      const detail = buildApiSamlFlowDetail(flowId);
      if (!detail) {
        sendJson(res, 404, { error: "SAML flow not found." });
        return true;
      }
      sendJson(res, 200, detail);
      return true;
    }

    // ---- JSON action endpoints (POST) ----
    // These reuse the same helpers as the SSR routes so RelayState,
    // request id and signing material are generated exactly once, in the
    // same code path. The response never contains the raw RelayState or
    // any signing key.

    const apiSamlStartMatch = req.method === "POST"
      ? url.pathname.match(/^\/api\/saml\/flows\/start\/([^/]+)$/)
      : null;
    if (apiSamlStartMatch) {
      const spId = decodeURIComponent(apiSamlStartMatch[1]);
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "saml-flow-start", 10, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return true;
      }
      const result = await startNewSamlUiFlow(session, spId, { httpMethod: "POST" });
      if (result.notFound) {
        sendJson(res, 404, { error: "SAML Service Provider not found." });
        return true;
      }
      if (!result.ok) {
        if (result.flow) {
          sendJson(res, 200, {
            next: "result_page",
            redirectUrl: `/saml/flows/${encodeURIComponent(result.flow.id)}`,
            flowId: result.flow.id,
            error: result.errorMessage || "SAML flow failed to start."
          });
          return true;
        }
        sendJson(res, 400, { error: result.errorMessage || "Failed to start SAML flow." });
        return true;
      }
      sendJson(res, 200, {
        next: "external_redirect",
        redirectUrl: result.authorizationUrl,
        flowId: result.flow?.id || null
      });
      return true;
    }

    const apiSamlRerunMatch = req.method === "POST"
      ? url.pathname.match(/^\/api\/saml\/flows\/([^/]+)\/rerun$/)
      : null;
    if (apiSamlRerunMatch) {
      const flowId = decodeURIComponent(apiSamlRerunMatch[1]);
      const existingFlow = samlFlowService.getFlow(flowId);
      if (!existingFlow) {
        sendJson(res, 404, { error: "SAML flow not found." });
        return true;
      }
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "saml-flow-start", 10, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return true;
      }
      const result = await startNewSamlUiFlow(session, existingFlow.serviceProviderId, { httpMethod: "POST" });
      if (result.notFound) {
        sendJson(res, 404, { error: "SAML Service Provider no longer exists." });
        return true;
      }
      if (!result.ok) {
        if (result.flow) {
          sendJson(res, 200, {
            next: "result_page",
            redirectUrl: `/saml/flows/${encodeURIComponent(result.flow.id)}`,
            flowId: result.flow.id,
            error: result.errorMessage || "SAML flow failed to restart."
          });
          return true;
        }
        sendJson(res, 400, { error: result.errorMessage || "Failed to restart SAML flow." });
        return true;
      }
      sendJson(res, 200, {
        next: "external_redirect",
        redirectUrl: result.authorizationUrl,
        flowId: result.flow?.id || null
      });
      return true;
    }

    return false;
  }

  return { handle };
}
