const STEP_ORDER = ["authorize", "callback", "token", "userinfo"];

function nowIso() {
  return new Date().toISOString();
}

function durationMs(startedAt, completedAt = nowIso()) {
  if (!startedAt) {
    return null;
  }

  const start = new Date(startedAt).getTime();
  const end = new Date(completedAt).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    return null;
  }

  return Math.max(0, end - start);
}

function normalizeFlow(flow = {}) {
  const startedAt = flow.startedAt || nowIso();
  return {
    id: flow.id || "",
    serviceProviderId: flow.serviceProviderId || "",
    status: ["running", "success", "failed", "partial_success"].includes(flow.status) ? flow.status : "running",
    startedAt,
    completedAt: flow.completedAt || null,
    failedStep: flow.failedStep || "",
    errorCode: flow.errorCode || "",
    errorDescription: flow.errorDescription || "",
    durationMs: flow.durationMs ?? (flow.completedAt ? durationMs(startedAt, flow.completedAt) : null),
    runtime: flow.runtime || null
  };
}

function normalizeStep(step = {}, { createId }) {
  const createdAt = step.createdAt || nowIso();
  return {
    id: step.id || createId("step"),
    flowId: step.flowId || "",
    stepName: STEP_ORDER.includes(step.stepName) ? step.stepName : "authorize",
    status: ["success", "error", "pending", "skipped"].includes(step.status) ? step.status : "pending",
    requestData: step.requestData || null,
    responseData: step.responseData || null,
    rawRequestData: step.rawRequestData || null,
    rawResponseData: step.rawResponseData || null,
    errorData: step.errorData || null,
    httpMethod: step.httpMethod || "",
    endpoint: step.endpoint || "",
    httpStatus: step.httpStatus ?? null,
    createdAt,
    completedAt: step.completedAt || null
  };
}

function sortFlows(entries = []) {
  return [...entries].sort((left, right) => {
    const leftTime = new Date(left.startedAt || 0).getTime();
    const rightTime = new Date(right.startedAt || 0).getTime();
    return rightTime - leftTime;
  });
}

function sortSteps(entries = []) {
  return [...entries].sort((left, right) => {
    const orderDelta = STEP_ORDER.indexOf(left.stepName) - STEP_ORDER.indexOf(right.stepName);
    if (orderDelta !== 0) {
      return orderDelta;
    }

    return new Date(left.createdAt || 0).getTime() - new Date(right.createdAt || 0).getTime();
  });
}

export function createFlowService({ getFlows, setFlows, getSteps, setSteps, createId, onChange = () => {} }) {
  function listFlows() {
    return sortFlows(getFlows());
  }

  function listRecentFlows(limit = 5) {
    return listFlows().slice(0, limit);
  }

  function listFlowsByServiceProvider(serviceProviderId) {
    return listFlows().filter((flow) => flow.serviceProviderId === serviceProviderId);
  }

  function getFlow(flowId) {
    return getFlows().find((flow) => flow.id === flowId) || null;
  }

  function getFlowSteps(flowId) {
    return sortSteps(getSteps().filter((step) => step.flowId === flowId));
  }

  function getFlowStep(flowId, stepName) {
    return getFlowSteps(flowId).find((step) => step.stepName === stepName) || null;
  }

  function getLastFlowForServiceProvider(serviceProviderId) {
    return listFlowsByServiceProvider(serviceProviderId)[0] || null;
  }

  function hydrateFlows(flows = [], steps = []) {
    setFlows(sortFlows(flows.map(normalizeFlow).filter((flow) => flow.id)));
    setSteps(sortSteps(steps.map((step) => normalizeStep(step, { createId })).filter((step) => step.flowId)));
  }

  function createFlow(serviceProviderId, runtime = null) {
    const flow = normalizeFlow({
      id: createId("flow"),
      serviceProviderId,
      status: "running",
      startedAt: nowIso(),
      runtime
    });

    setFlows(sortFlows([...getFlows(), flow]));
    onChange();
    return flow;
  }

  function updateFlow(flowId, patch = {}) {
    const existing = getFlow(flowId);
    if (!existing) {
      return null;
    }

    const next = normalizeFlow({
      ...existing,
      ...patch
    });

    if (next.completedAt && next.durationMs === null) {
      next.durationMs = durationMs(next.startedAt, next.completedAt);
    }

    setFlows(sortFlows(getFlows().map((flow) => (flow.id === flowId ? next : flow))));
    onChange();
    return next;
  }

  function completeFlow(flowId, patch = {}) {
    const completedAt = patch.completedAt || nowIso();
    return updateFlow(flowId, {
      ...patch,
      completedAt,
      durationMs: durationMs(getFlow(flowId)?.startedAt, completedAt)
    });
  }

  function addFlowStep(flowId, step = {}) {
    const normalized = normalizeStep(
      {
        ...step,
        flowId,
        id: step.id || getFlowStep(flowId, step.stepName)?.id
      },
      { createId }
    );
    const existing = getSteps().some((entry) => entry.id === normalized.id);
    const nextSteps = existing
      ? getSteps().map((entry) => (entry.id === normalized.id ? normalized : entry))
      : [...getSteps(), normalized];

    setSteps(sortSteps(nextSteps));
    onChange();
    return normalized;
  }

  function findRunningFlowByState(state) {
    if (!state) {
      return null;
    }

    return getFlows().find((flow) => flow.status === "running" && flow.runtime?.expectedState === state) || null;
  }

  return {
    listFlows,
    listRecentFlows,
    listFlowsByServiceProvider,
    getFlow,
    createFlow,
    completeFlow,
    updateFlow,
    addFlowStep,
    getFlowSteps,
    getLastFlowForServiceProvider,
    findRunningFlowByState,
    hydrateFlows
  };
}

export { STEP_ORDER };
