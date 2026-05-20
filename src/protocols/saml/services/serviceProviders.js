import { getEzAccessEnvironment } from "../../../common/views/config.js";

const MAX_NAME_LENGTH = 255;
const MAX_ENTITY_ID_LENGTH = 512;
const MAX_METADATA_URL_LENGTH = 2048;
const MAX_METADATA_XML_LENGTH = 65536;

function clean(value = "") {
  return String(value ?? "").trim();
}

export function validateSamlServiceProviderInput(input = {}) {
  const rawMetadataMode = clean(input.idpMetadataMode);
  const rawIdpMetadataUrl = clean(input.idpMetadataUrl);
  const rawIdpMetadataXml = clean(input.idpMetadataXml);
  const metadataMode = rawMetadataMode === "xml"
    ? "xml"
    : rawMetadataMode === "url" || rawIdpMetadataUrl || !rawIdpMetadataXml
      ? "url"
      : "xml";
  const idpMetadataUrl = metadataMode === "url" ? rawIdpMetadataUrl : "";
  const idpMetadataXml = metadataMode === "xml" ? rawIdpMetadataXml : "";
  const values = {
    name: clean(input.name),
    environment: clean(input.environment),
    spEntityId: clean(input.spEntityId),
    idpMetadataMode: metadataMode,
    idpMetadataUrl,
    idpMetadataXml
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

  if (!values.spEntityId) {
    errors.spEntityId = "SP Entity ID is required.";
  } else if (values.spEntityId.length > MAX_ENTITY_ID_LENGTH) {
    errors.spEntityId = `SP Entity ID must be ${MAX_ENTITY_ID_LENGTH} characters or fewer.`;
  }

  if (values.idpMetadataUrl.length > MAX_METADATA_URL_LENGTH) {
    errors.idpMetadataUrl = `IdP Metadata URL must be ${MAX_METADATA_URL_LENGTH} characters or fewer.`;
  }

  if (values.idpMetadataXml.length > MAX_METADATA_XML_LENGTH) {
    errors.idpMetadataXml = `IdP Metadata XML must be ${MAX_METADATA_XML_LENGTH} characters or fewer.`;
  }

  if (!values.idpMetadataUrl && !values.idpMetadataXml) {
    warnings.push("IdP Metadata URL or XML is recommended to configure the IdP connection.");
  }

  return {
    values,
    errors,
    warnings,
    valid: Object.keys(errors).length === 0
  };
}

export function samlServiceProviderStatus(serviceProvider) {
  const ready = Boolean(
    serviceProvider?.name &&
    serviceProvider?.environment &&
    getEzAccessEnvironment(serviceProvider.environment) &&
    serviceProvider?.spEntityId &&
    (serviceProvider?.idpMetadataUrl || serviceProvider?.idpMetadataXml)
  );
  return ready
    ? { label: "Ready", tone: "success" }
    : { label: "Incomplete", tone: "warning" };
}

function normalizePersistedSamlSp(entry, { createId }) {
  const now = new Date().toISOString();
  return {
    id: clean(entry.id) || createId("saml_sp"),
    name: clean(entry.name),
    environment: getEzAccessEnvironment(entry.environment)?.key || "",
    spEntityId: clean(entry.spEntityId),
    idpMetadataUrl: clean(entry.idpMetadataUrl),
    idpMetadataXml: clean(entry.idpMetadataXml),
    createdAt: entry.createdAt || now,
    updatedAt: entry.updatedAt || now
  };
}

function sortSamlServiceProviders(entries = []) {
  return [...entries].sort((a, b) => {
    const nameA = a.name || a.spEntityId || "";
    const nameB = b.name || b.spEntityId || "";
    return nameA.localeCompare(nameB, "fr");
  });
}

export function createSamlServiceProviderService({ getEntries, setEntries, createId, onChange = () => {} }) {
  function listSamlServiceProviders() {
    return sortSamlServiceProviders(getEntries());
  }

  function getSamlServiceProvider(id) {
    return getEntries().find((entry) => entry.id === id) || null;
  }

  function hydrateSamlServiceProviders(entries = []) {
    const normalized = sortSamlServiceProviders(
      entries.map((entry) => normalizePersistedSamlSp(entry, { createId })).filter((sp) => sp.id)
    );
    setEntries(normalized);
    return normalized;
  }

  function createSamlServiceProvider(input = {}) {
    const validation = validateSamlServiceProviderInput(input);
    if (!validation.valid) {
      return { ok: false, validation };
    }

    const now = new Date().toISOString();
    const id = createId("saml_sp");
    const sp = {
      id,
      name: validation.values.name,
      environment: validation.values.environment,
      spEntityId: validation.values.spEntityId,
      idpMetadataUrl: validation.values.idpMetadataUrl,
      idpMetadataXml: validation.values.idpMetadataXml,
      createdAt: now,
      updatedAt: now
    };

    setEntries(sortSamlServiceProviders([...getEntries(), sp]));
    onChange();
    return { ok: true, serviceProvider: sp, validation };
  }

  function updateSamlServiceProvider(id, input = {}) {
    const existing = getSamlServiceProvider(id);
    if (!existing) {
      return { ok: false, notFound: true };
    }

    const validation = validateSamlServiceProviderInput(input);
    if (!validation.valid) {
      return { ok: false, validation, serviceProvider: existing };
    }

    const sp = {
      ...existing,
      name: validation.values.name,
      environment: validation.values.environment,
      spEntityId: validation.values.spEntityId,
      idpMetadataUrl: validation.values.idpMetadataUrl,
      idpMetadataXml: validation.values.idpMetadataXml,
      updatedAt: new Date().toISOString()
    };

    setEntries(sortSamlServiceProviders(getEntries().map((entry) => (entry.id === id ? sp : entry))));
    onChange();
    return { ok: true, serviceProvider: sp, validation };
  }

  function deleteSamlServiceProvider(id) {
    const before = getEntries().length;
    setEntries(getEntries().filter((entry) => entry.id !== id));
    const removed = getEntries().length !== before;
    if (removed) onChange();
    return removed;
  }

  return {
    listSamlServiceProviders,
    getSamlServiceProvider,
    hydrateSamlServiceProviders,
    createSamlServiceProvider,
    updateSamlServiceProvider,
    deleteSamlServiceProvider
  };
}
