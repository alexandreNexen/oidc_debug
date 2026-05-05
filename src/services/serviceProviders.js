import { normalizeServiceProvider } from "../oidc.js";
import { getEzAccessEnvironment } from "../config.js";

const MAX_NAME_LENGTH = 255;
const MAX_CLIENT_ID_LENGTH = 256;
const MAX_CLIENT_SECRET_LENGTH = 512;
const MAX_SCOPES_LENGTH = 512;

function clean(value = "") {
  return String(value ?? "").trim();
}

function getInputValue(input = {}, camelName, snakeName = camelName) {
  if (input[camelName] !== undefined) {
    return input[camelName];
  }

  return input[snakeName];
}

export function normalizeScopes(value = "") {
  return clean(value).replace(/\s+/g, " ");
}

export function validateServiceProviderInput(input = {}, { mode = "create" } = {}) {
  const values = {
    name: clean(getInputValue(input, "name")),
    environment: clean(getInputValue(input, "environment")),
    clientId: clean(getInputValue(input, "clientId", "client_id")),
    clientSecret: clean(getInputValue(input, "clientSecret", "client_secret")),
    scopes: normalizeScopes(getInputValue(input, "scopes"))
  };
  const errors = {};
  const warnings = [];

  if (!values.name) {
    errors.name = "Name is required.";
  } else if (values.name.length > MAX_NAME_LENGTH) {
    errors.name = `Name must be ${MAX_NAME_LENGTH} characters or fewer.`;
  }

  if (!values.environment || !getEzAccessEnvironment(values.environment)) {
    errors.environment = "Environment is required.";
  }

  if (!values.clientId) {
    errors.client_id = "Client ID is required.";
  } else if (values.clientId.length > MAX_CLIENT_ID_LENGTH) {
    errors.client_id = `Client ID must be ${MAX_CLIENT_ID_LENGTH} characters or fewer.`;
  }

  if (mode === "create" && !values.clientSecret) {
    errors.client_secret = "Client Secret is required.";
  } else if (values.clientSecret && values.clientSecret.length > MAX_CLIENT_SECRET_LENGTH) {
    errors.client_secret = `Client Secret must be ${MAX_CLIENT_SECRET_LENGTH} characters or fewer.`;
  }

  if (!values.scopes) {
    errors.scopes = "Scopes are required.";
  } else if (values.scopes.length > MAX_SCOPES_LENGTH) {
    errors.scopes = `Scopes must be ${MAX_SCOPES_LENGTH} characters or fewer.`;
  }

  if (values.scopes && !values.scopes.split(" ").includes("openid")) {
    warnings.push("Scope openid is recommended for OIDC flows.");
  }

  return {
    values,
    errors,
    warnings,
    valid: Object.keys(errors).length === 0
  };
}

export function isServiceProviderReady(serviceProvider) {
  return Boolean(
      serviceProvider?.name &&
      serviceProvider?.environment &&
      getEzAccessEnvironment(serviceProvider.environment) &&
      serviceProvider?.clientId &&
      serviceProvider?.scopes &&
      serviceProvider?.secretRecord?.ciphertext
  );
}

export function serviceProviderStatus(serviceProvider) {
  return isServiceProviderReady(serviceProvider)
    ? { label: "Ready", tone: "success" }
    : { label: "Missing", tone: "warning" };
}

function normalizePersistedServiceProvider(entry, { createId }) {
  const normalized = normalizeServiceProvider(
    {
      ...entry,
      clientId: entry.clientId ?? entry.client_id
    },
    entry
  );
  const now = new Date().toISOString();

  return {
    id: normalized.id || createId("sp"),
    name: normalized.name,
    environment: getEzAccessEnvironment(entry.environment)?.key || "",
    clientId: normalized.clientId,
    clientType: normalized.clientType || "confidential",
    scopes: normalizeScopes(normalized.scopes),
    secretRecord: entry.secretRecord || null,
    createdAt: entry.createdAt || entry.created_at || now,
    updatedAt: entry.updatedAt || entry.updated_at || now
  };
}

export function sortServiceProviders(entries = []) {
  return [...entries].sort((left, right) => {
    const leftName = left.name || left.clientId || "";
    const rightName = right.name || right.clientId || "";
    return leftName.localeCompare(rightName, "fr");
  });
}

export function createServiceProviderService({ getEntries, setEntries, createId, encryptSecret, onChange = () => {} }) {
  function listServiceProviders() {
    return sortServiceProviders(getEntries());
  }

  function getServiceProvider(id) {
    return getEntries().find((entry) => entry.id === id) || null;
  }

  function hydrateServiceProviders(entries = []) {
    const nextEntries = sortServiceProviders(
      entries.map((entry) => normalizePersistedServiceProvider(entry, { createId }))
    );
    setEntries(nextEntries);
    return nextEntries;
  }

  function createServiceProvider(input = {}) {
    const validation = validateServiceProviderInput(input, { mode: "create" });
    if (!validation.valid) {
      return { ok: false, validation };
    }

    const now = new Date().toISOString();
    const serviceProvider = {
      id: createId("sp"),
      name: validation.values.name,
      environment: validation.values.environment,
      clientId: validation.values.clientId,
      clientType: "confidential",
      scopes: validation.values.scopes,
      secretRecord: encryptSecret(validation.values.clientSecret),
      createdAt: now,
      updatedAt: now
    };

    setEntries(sortServiceProviders([...getEntries(), serviceProvider]));
    onChange();

    return {
      ok: true,
      serviceProvider,
      isNew: true,
      secretUpdated: true,
      validation
    };
  }

  function updateServiceProvider(id, input = {}) {
    const existing = getServiceProvider(id);
    if (!existing) {
      return { ok: false, notFound: true };
    }

    const validation = validateServiceProviderInput(input, { mode: "edit" });
    if (!validation.valid) {
      return { ok: false, validation, serviceProvider: existing };
    }

    const secretUpdated = Boolean(validation.values.clientSecret);
    const serviceProvider = {
      ...existing,
      name: validation.values.name,
      environment: validation.values.environment,
      clientId: validation.values.clientId,
      clientType: "confidential",
      scopes: validation.values.scopes,
      secretRecord: secretUpdated ? encryptSecret(validation.values.clientSecret) : existing.secretRecord,
      updatedAt: new Date().toISOString()
    };

    setEntries(sortServiceProviders(getEntries().map((entry) => (entry.id === existing.id ? serviceProvider : entry))));
    onChange();

    return {
      ok: true,
      serviceProvider,
      isNew: false,
      secretUpdated,
      validation
    };
  }

  function upsertServiceProvider(input = {}, rawSecret = "") {
    const normalized = normalizeServiceProvider(
      {
        ...input,
        clientId: input.clientId ?? input.client_id,
        scopes: normalizeScopes(input.scopes)
      },
      input.id ? getServiceProvider(input.id) || {} : {}
    );
    const existing = normalized.id ? getServiceProvider(normalized.id) : null;
    const now = new Date().toISOString();
    const serviceProvider = {
      id: normalized.id || createId("sp"),
      name: normalized.name,
      environment: getEzAccessEnvironment(input.environment || existing?.environment)?.key || "",
      clientId: normalized.clientId,
      clientType: normalized.clientType || "confidential",
      scopes: normalizeScopes(normalized.scopes),
      secretRecord: existing?.secretRecord || null,
      createdAt: existing?.createdAt || now,
      updatedAt: now
    };

    if (serviceProvider.clientType === "confidential" && rawSecret) {
      serviceProvider.secretRecord = encryptSecret(rawSecret);
    }

    setEntries(
      sortServiceProviders(
        existing
          ? getEntries().map((entry) => (entry.id === existing.id ? serviceProvider : entry))
          : [...getEntries(), serviceProvider]
      )
    );
    onChange();

    return {
      serviceProvider,
      isNew: !existing,
      secretUpdated: Boolean(serviceProvider.clientType === "confidential" && rawSecret)
    };
  }

  function deleteServiceProvider(id) {
    const before = getEntries().length;
    setEntries(getEntries().filter((entry) => entry.id !== id));
    const removed = getEntries().length !== before;

    if (removed) {
      onChange();
    }

    return removed;
  }

  return {
    listServiceProviders,
    getServiceProvider,
    hydrateServiceProviders,
    createServiceProvider,
    updateServiceProvider,
    deleteServiceProvider,
    upsertServiceProvider
  };
}
