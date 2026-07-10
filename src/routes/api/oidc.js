// OIDC JSON API endpoints served under /api/oidc/*. Extracted verbatim
// from the pre-refactor server.js inline block — identical URLs, methods,
// status codes, payloads, rate-limit budgets and error messages. All
// dependencies are injected through the factory so this module has no
// hidden global state.
//
// Endpoints handled here:
//   GET    /api/oidc/environments
//   GET    /api/oidc/service-providers
//   GET    /api/oidc/service-providers/:spId
//   POST   /api/oidc/service-providers
//   PATCH  /api/oidc/service-providers/:spId
//   DELETE /api/oidc/service-providers/:spId
//   GET    /api/oidc/flows
//   GET    /api/oidc/flows/:flowId
//   POST   /api/oidc/flows/start/:spId
//   POST   /api/oidc/flows/:flowId/rerun
//   POST   /api/oidc/discovery/import/:env
//
// The cross-site guard (`assertApiPostAllowed`) is applied ONCE by the
// root API router (see routes/api/index.js) before delegation, so nothing
// here has to repeat it.

export function createOidcApiRouter({ http, security, sessions, oidc }) {
  const { sendJson, readBody, parseBody } = http;
  const { checkRateLimit } = security;
  const { getOrCreateSession, touchSession, addSessionLog, resetFlowState } = sessions;
  const {
    serviceProviderService,
    flowService,
    removeServiceProvider,
    sanitizeServiceProviderForUi,
    listEzAccessEnvironments,
    sanitizeEzAccessEnvironmentForUi,
    apiFlowSummary,
    buildApiOidcFlowDetail,
    startNewUiFlow,
    handleOidcDiscoveryImport
  } = oidc;

  async function handle(req, res, url) {
    if (!url.pathname.startsWith("/api/oidc/")) return false;

    if (req.method === "GET" && url.pathname === "/api/oidc/environments") {
      const items = listEzAccessEnvironments().map(sanitizeEzAccessEnvironmentForUi);
      sendJson(res, 200, { items });
      return true;
    }

    if (req.method === "GET" && url.pathname === "/api/oidc/service-providers") {
      const items = serviceProviderService.listServiceProviders().map(sanitizeServiceProviderForUi);
      sendJson(res, 200, { items });
      return true;
    }

    // ---- OIDC Service Provider write endpoints ----
    // Reuse `serviceProviderService.createServiceProvider` /
    // `updateServiceProvider` so validation, secret encryption and
    // persistence go through exactly one code path. The client_secret /
    // secretRecord are never returned to the caller.

    const apiOidcSpDetailMatch = req.method === "GET"
      ? url.pathname.match(/^\/api\/oidc\/service-providers\/([^/]+)$/)
      : null;
    if (apiOidcSpDetailMatch) {
      const spId = decodeURIComponent(apiOidcSpDetailMatch[1]);
      const sp = serviceProviderService.getServiceProvider(spId);
      if (!sp) {
        sendJson(res, 404, { error: "Service Provider not found." });
        return true;
      }
      sendJson(res, 200, { serviceProvider: sanitizeServiceProviderForUi(sp) });
      return true;
    }

    if (req.method === "POST" && url.pathname === "/api/oidc/service-providers") {
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "sp-create", 20, 5 * 60 * 1000)) {
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
      const result = serviceProviderService.createServiceProvider(body);
      if (!result.ok) {
        sendJson(res, 400, {
          error: "Please fix the highlighted fields.",
          fieldErrors: result.validation.errors,
          warnings: result.validation.warnings
        });
        return true;
      }
      session.selectedServiceProviderId = result.serviceProvider.id;
      touchSession(session);
      addSessionLog(session, "info", "service_provider_created", "Service Provider created.", {
        serviceProvider: sanitizeServiceProviderForUi(result.serviceProvider)
      });
      sendJson(res, 200, {
        id: result.serviceProvider.id,
        redirectUrl: "/oidc/service-providers",
        warnings: result.validation.warnings
      });
      return true;
    }

    const apiOidcSpUpdateMatch = req.method === "PATCH"
      ? url.pathname.match(/^\/api\/oidc\/service-providers\/([^/]+)$/)
      : null;
    if (apiOidcSpUpdateMatch) {
      const spId = decodeURIComponent(apiOidcSpUpdateMatch[1]);
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "sp-create", 20, 5 * 60 * 1000)) {
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
      const result = serviceProviderService.updateServiceProvider(spId, body);
      if (result.notFound) {
        sendJson(res, 404, { error: "Service Provider not found." });
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
      if (session.selectedServiceProviderId === result.serviceProvider.id) {
        resetFlowState(session, "service_provider_update");
      } else {
        touchSession(session);
      }
      addSessionLog(session, "info", "service_provider_updated", "Service Provider updated.", {
        serviceProvider: sanitizeServiceProviderForUi(result.serviceProvider),
        secretUpdated: result.secretUpdated
      });
      sendJson(res, 200, {
        id: result.serviceProvider.id,
        redirectUrl: "/oidc/service-providers",
        secretUpdated: result.secretUpdated,
        warnings: result.validation.warnings
      });
      return true;
    }

    const apiOidcSpDeleteMatch = req.method === "DELETE"
      ? url.pathname.match(/^\/api\/oidc\/service-providers\/([^/]+)$/)
      : null;
    if (apiOidcSpDeleteMatch) {
      const spId = decodeURIComponent(apiOidcSpDeleteMatch[1]);
      const session = getOrCreateSession(req, res);
      // Reuse `removeServiceProvider` so we share exactly one code path
      // with the SSR delete: it clears the SP entry, resets `selectedSp`
      // on every session that pointed at it, and schedules a state.json
      // persist. Historical flow records referencing this SP are kept
      // intact for post-mortem — same behavior as SSR.
      if (!removeServiceProvider(spId)) {
        sendJson(res, 404, { error: "Service Provider not found." });
        return true;
      }
      addSessionLog(session, "info", "service_provider_deleted", "Service Provider deleted.", {
        serviceProviderId: spId
      });
      sendJson(res, 200, {
        deleted: true,
        id: spId,
        redirectUrl: "/oidc/service-providers"
      });
      return true;
    }

    if (req.method === "GET" && url.pathname === "/api/oidc/flows") {
      const items = flowService.listFlows().map(apiFlowSummary);
      sendJson(res, 200, { items });
      return true;
    }

    const apiOidcFlowMatch = req.method === "GET" ? url.pathname.match(/^\/api\/oidc\/flows\/([^/]+)$/) : null;
    if (apiOidcFlowMatch) {
      const flowId = decodeURIComponent(apiOidcFlowMatch[1]);
      const detail = buildApiOidcFlowDetail(flowId);
      if (!detail) {
        sendJson(res, 404, { error: "OIDC flow not found." });
        return true;
      }
      sendJson(res, 200, detail);
      return true;
    }

    // ---- JSON action endpoints (POST) ----
    // These reuse the same helpers as the SSR routes so state / nonce /
    // PKCE are generated exactly once, in the same code path. The response
    // never contains client_secret, code_verifier or the cleartext
    // state/nonce.

    const apiOidcStartMatch = req.method === "POST"
      ? url.pathname.match(/^\/api\/oidc\/flows\/start\/([^/]+)$/)
      : null;
    if (apiOidcStartMatch) {
      const spId = decodeURIComponent(apiOidcStartMatch[1]);
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "flow-start", 10, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return true;
      }
      const result = await startNewUiFlow(session, spId);
      if (result.notFound) {
        sendJson(res, 404, { error: "Service Provider not found." });
        return true;
      }
      if (!result.ok) {
        sendJson(res, 200, {
          next: "result_page",
          redirectUrl: result.flow
            ? `/oidc/flows/${encodeURIComponent(result.flow.id)}`
            : "/oidc/service-providers",
          flowId: result.flow?.id || null,
          error: "Flow failed to start. Open the flow detail for diagnostics."
        });
        return true;
      }
      sendJson(res, 200, {
        next: "external_redirect",
        redirectUrl: result.authorizationUrl,
        flowId: result.flow?.id || null
      });
      return true;
    }

    const apiOidcRerunMatch = req.method === "POST"
      ? url.pathname.match(/^\/api\/oidc\/flows\/([^/]+)\/rerun$/)
      : null;
    if (apiOidcRerunMatch) {
      const flowId = decodeURIComponent(apiOidcRerunMatch[1]);
      const existingFlow = flowService.getFlow(flowId);
      if (!existingFlow) {
        sendJson(res, 404, { error: "OIDC flow not found." });
        return true;
      }
      const session = getOrCreateSession(req, res);
      if (!checkRateLimit(session.id, "flow-start", 10, 5 * 60 * 1000)) {
        sendJson(res, 429, { error: "Too many requests. Please wait before retrying." });
        return true;
      }
      const result = await startNewUiFlow(session, existingFlow.serviceProviderId);
      if (result.notFound) {
        sendJson(res, 404, { error: "Service Provider no longer exists." });
        return true;
      }
      if (!result.ok) {
        sendJson(res, 200, {
          next: "result_page",
          redirectUrl: result.flow
            ? `/oidc/flows/${encodeURIComponent(result.flow.id)}`
            : "/oidc/service-providers",
          flowId: result.flow?.id || null,
          error: "Flow failed to restart. Open the flow detail for diagnostics."
        });
        return true;
      }
      sendJson(res, 200, {
        next: "external_redirect",
        redirectUrl: result.authorizationUrl,
        flowId: result.flow?.id || null
      });
      return true;
    }

    const apiDiscoveryImportMatch = req.method === "POST"
      ? url.pathname.match(/^\/api\/oidc\/discovery\/import\/(preprod|prod)$/)
      : null;
    if (apiDiscoveryImportMatch) {
      const session = getOrCreateSession(req, res);
      await handleOidcDiscoveryImport({
        req,
        res,
        environmentKey: apiDiscoveryImportMatch[1],
        sessionId: session.id
      });
      return true;
    }

    return false;
  }

  return { handle };
}
