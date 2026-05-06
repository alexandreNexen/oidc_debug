import { getEzAccessEnvironment } from "../../oidc/config.js";

const MAX_NAME_LENGTH = 255;
const MAX_ENTITY_ID_LENGTH = 512;
const MAX_METADATA_URL_LENGTH = 2048;
const MAX_METADATA_XML_LENGTH = 65536;
const MAX_ACS_URL_LENGTH = 2048;
const MAX_LOGOUT_URL_LENGTH = 2048;
const MAX_ATTRIBUTES_LENGTH = 4096;
const MAX_NOTES_LENGTH = 4096;

const VALID_NAME_ID_FORMATS = [
  "",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
];

function clean(value = "") {
  return String(value ?? "").trim();
}

function parseBool(value) {
  return value === true || value === "on" || value === "true";
}

export function validateSamlServiceProviderInput(input = {}) {
  const values = {
    name: clean(input.name),
    environment: clean(input.environment),
    idpMetadataUrl: clean(input.idpMetadataUrl),
    idpMetadataXml: clean(input.idpMetadataXml),
    spEntityId: clean(input.spEntityId),
    debugAcsUrl: clean(input.debugAcsUrl),
    nameIdFormat: clean(input.nameIdFormat),
    requestSigned: parseBool(input.requestSigned),
    wantResponseSigned: parseBool(input.wantResponseSigned),
    wantAssertionSigned: parseBool(input.wantAssertionSigned),
    requiredAttributes: clean(input.requiredAttributes),
    accessControlNotes: clean(input.accessControlNotes),
    logoutUrl: clean(input.logoutUrl)
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

  if (values.debugAcsUrl.length > MAX_ACS_URL_LENGTH) {
    errors.debugAcsUrl = `ACS URL must be ${MAX_ACS_URL_LENGTH} characters or fewer.`;
  }

  if (values.logoutUrl.length > MAX_LOGOUT_URL_LENGTH) {
    errors.logoutUrl = `Logout URL must be ${MAX_LOGOUT_URL_LENGTH} characters or fewer.`;
  }

  if (values.requiredAttributes.length > MAX_ATTRIBUTES_LENGTH) {
    errors.requiredAttributes = `Required attributes must be ${MAX_ATTRIBUTES_LENGTH} characters or fewer.`;
  }

  if (values.accessControlNotes.length > MAX_NOTES_LENGTH) {
    errors.accessControlNotes = `Access control notes must be ${MAX_NOTES_LENGTH} characters or fewer.`;
  }

  if (values.nameIdFormat && !VALID_NAME_ID_FORMATS.includes(values.nameIdFormat)) {
    errors.nameIdFormat = "Unknown NameID format.";
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
    idpMetadataUrl: clean(entry.idpMetadataUrl),
    idpMetadataXml: clean(entry.idpMetadataXml),
    spEntityId: clean(entry.spEntityId),
    debugAcsUrl: clean(entry.debugAcsUrl),
    nameIdFormat: VALID_NAME_ID_FORMATS.includes(clean(entry.nameIdFormat)) ? clean(entry.nameIdFormat) : "",
    requestSigned: Boolean(entry.requestSigned),
    wantResponseSigned: Boolean(entry.wantResponseSigned),
    wantAssertionSigned: Boolean(entry.wantAssertionSigned),
    requiredAttributes: clean(entry.requiredAttributes),
    accessControlNotes: clean(entry.accessControlNotes),
    logoutUrl: clean(entry.logoutUrl),
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

export function createSamlServiceProviderService({ getEntries, setEntries, createId, computeAcsUrl, onChange = () => {} }) {
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
      idpMetadataUrl: validation.values.idpMetadataUrl,
      idpMetadataXml: validation.values.idpMetadataXml,
      spEntityId: validation.values.spEntityId,
      debugAcsUrl: validation.values.debugAcsUrl || (computeAcsUrl ? computeAcsUrl(id) : ""),
      nameIdFormat: validation.values.nameIdFormat,
      requestSigned: validation.values.requestSigned,
      wantResponseSigned: validation.values.wantResponseSigned,
      wantAssertionSigned: validation.values.wantAssertionSigned,
      requiredAttributes: validation.values.requiredAttributes,
      accessControlNotes: validation.values.accessControlNotes,
      logoutUrl: validation.values.logoutUrl,
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
      idpMetadataUrl: validation.values.idpMetadataUrl,
      idpMetadataXml: validation.values.idpMetadataXml,
      spEntityId: validation.values.spEntityId,
      debugAcsUrl: validation.values.debugAcsUrl || existing.debugAcsUrl || (computeAcsUrl ? computeAcsUrl(id) : ""),
      nameIdFormat: validation.values.nameIdFormat,
      requestSigned: validation.values.requestSigned,
      wantResponseSigned: validation.values.wantResponseSigned,
      wantAssertionSigned: validation.values.wantAssertionSigned,
      requiredAttributes: validation.values.requiredAttributes,
      accessControlNotes: validation.values.accessControlNotes,
      logoutUrl: validation.values.logoutUrl,
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
