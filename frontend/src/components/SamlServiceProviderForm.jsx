import React, { useCallback, useEffect, useState } from "react";
import { getOidcEnvironments } from "../api/client.js";

// Shared SAML Service Provider form used by the new and edit pages.
//
// Backend contract — only these fields are accepted:
//   - name (required)
//   - environment (required)
//   - spEntityId (required)
//   - idpMetadataMode ("url" | "xml", auto-inferred if omitted)
//   - idpMetadataUrl (when mode=url)
//   - idpMetadataXml (when mode=xml)
//
// `nameIdFormat` and `requestSigned` are not accepted by the SAML SP service.
// Legacy values still on disk remain untouched on update.
export default function SamlServiceProviderForm({
  mode,
  initial = null,
  acsUrl = "",
  onSubmit,
  submitLabel,
  cancelHref
}) {
  const [envState, setEnvState] = useState({ status: "loading", items: [], error: "" });
  const [formError, setFormError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});
  const [warnings, setWarnings] = useState([]);
  const [busy, setBusy] = useState(false);

  const [name, setName] = useState(initial?.name || "");
  const [environment, setEnvironment] = useState(initial?.environment || "");
  const [spEntityId, setSpEntityId] = useState(initial?.spEntityId || "");
  const initialMode =
    initial?.idpMetadataMode ||
    (initial?.idpMetadataXml && !initial?.idpMetadataUrl ? "xml" : "url");
  const [metadataMode, setMetadataMode] = useState(initialMode);
  const [idpMetadataUrl, setIdpMetadataUrl] = useState(initial?.idpMetadataUrl || "");
  const [idpMetadataXml, setIdpMetadataXml] = useState(initial?.idpMetadataXml || "");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const payload = await getOidcEnvironments();
        if (cancelled) return;
        const items = Array.isArray(payload?.items) ? payload.items : [];
        setEnvState({ status: "ready", items, error: "" });
      } catch (error) {
        if (cancelled) return;
        setEnvState({
          status: "error",
          items: [],
          error: error && error.message ? error.message : "Unable to load environments."
        });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSubmit = useCallback(
    async (event) => {
      event.preventDefault();
      if (busy) return;

      const payload = {
        name: name.trim(),
        environment: environment.trim(),
        spEntityId: spEntityId.trim(),
        idpMetadataMode: metadataMode
      };
      if (metadataMode === "url") {
        payload.idpMetadataUrl = idpMetadataUrl.trim();
        payload.idpMetadataXml = "";
      } else {
        payload.idpMetadataXml = idpMetadataXml;
        payload.idpMetadataUrl = "";
      }

      setBusy(true);
      setFormError("");
      setFieldErrors({});
      setWarnings([]);

      try {
        const response = await onSubmit(payload);
        if (response && Array.isArray(response.warnings)) {
          setWarnings(response.warnings);
        }
        const redirectUrl =
          response && typeof response.redirectUrl === "string" ? response.redirectUrl : "";
        if (redirectUrl) {
          window.location.assign(redirectUrl);
          return;
        }
      } catch (error) {
        const message = error && error.message ? error.message : "Request failed.";
        setFormError(message);
        if (error && error.fieldErrors) {
          setFieldErrors(error.fieldErrors);
        }
        if (error && Array.isArray(error.warnings)) {
          setWarnings(error.warnings);
        }
      } finally {
        setBusy(false);
      }
    },
    [busy, environment, idpMetadataUrl, idpMetadataXml, metadataMode, name, onSubmit, spEntityId]
  );

  const envDisabled = envState.status !== "ready" || busy;

  return (
    <form className="sp-form" onSubmit={handleSubmit} noValidate>
      {acsUrl ? (
        <div className="redirect-uri-block" style={{ marginBottom: "1rem" }}>
          <span className="redirect-uri-block__label">ACS URL</span>
          <code className="code-inline redirect-uri-block__uri">{acsUrl}</code>
          <p className="muted" style={{ marginTop: "0.25rem" }}>
            L&apos;ACS URL est dérivée automatiquement de l&apos;ID du Service Provider.
          </p>
        </div>
      ) : null}

      {formError ? (
        <div className="alert alert--error" role="alert">
          <strong>{formError}</strong>
        </div>
      ) : null}
      {warnings.length ? (
        <div className="alert alert--warning" role="status">
          <ul>
            {warnings.map((warning, idx) => (
              <li key={idx}>{warning}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="sp-form__field">
        <label htmlFor="field-name">Name</label>
        <input
          id="field-name"
          name="name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          aria-invalid={fieldErrors.name ? "true" : undefined}
        />
        {fieldErrors.name ? <p className="field-error">{fieldErrors.name}</p> : null}
      </div>

      <div className="sp-form__field">
        <label htmlFor="field-environment">Environment</label>
        <select
          id="field-environment"
          name="environment"
          value={environment}
          onChange={(e) => setEnvironment(e.target.value)}
          disabled={envDisabled}
          required
          aria-invalid={fieldErrors.environment ? "true" : undefined}
        >
          <option value="">
            {envState.status === "loading" ? "Loading environments…" : "Select Ez-Access environment"}
          </option>
          {envState.items.map((env) => (
            <option key={env.key} value={env.key}>
              {env.label || env.key}
            </option>
          ))}
        </select>
        {envState.status === "error" ? <p className="field-error">{envState.error}</p> : null}
        {fieldErrors.environment ? <p className="field-error">{fieldErrors.environment}</p> : null}
      </div>

      <div className="sp-form__field">
        <label htmlFor="field-spEntityId">SP Entity ID</label>
        <input
          id="field-spEntityId"
          name="spEntityId"
          type="text"
          value={spEntityId}
          onChange={(e) => setSpEntityId(e.target.value)}
          required
          aria-invalid={fieldErrors.spEntityId ? "true" : undefined}
        />
        {fieldErrors.spEntityId ? <p className="field-error">{fieldErrors.spEntityId}</p> : null}
      </div>

      <fieldset className="sp-form__field">
        <legend>IdP Metadata</legend>
        <div role="radiogroup" aria-label="IdP Metadata mode" style={{ display: "flex", gap: "1rem", marginBottom: "0.5rem" }}>
          <label>
            <input
              type="radio"
              name="idpMetadataMode"
              value="url"
              checked={metadataMode === "url"}
              onChange={() => setMetadataMode("url")}
            />{" "}
            URL
          </label>
          <label>
            <input
              type="radio"
              name="idpMetadataMode"
              value="xml"
              checked={metadataMode === "xml"}
              onChange={() => setMetadataMode("xml")}
            />{" "}
            XML
          </label>
        </div>

        {metadataMode === "url" ? (
          <>
            <input
              id="field-idpMetadataUrl"
              name="idpMetadataUrl"
              type="url"
              value={idpMetadataUrl}
              onChange={(e) => setIdpMetadataUrl(e.target.value)}
              placeholder="https://idp.example.com/metadata"
              aria-invalid={fieldErrors.idpMetadataUrl ? "true" : undefined}
            />
            {fieldErrors.idpMetadataUrl ? (
              <p className="field-error">{fieldErrors.idpMetadataUrl}</p>
            ) : null}
          </>
        ) : (
          <>
            <textarea
              id="field-idpMetadataXml"
              name="idpMetadataXml"
              rows={8}
              value={idpMetadataXml}
              onChange={(e) => setIdpMetadataXml(e.target.value)}
              placeholder={"<?xml version=\"1.0\"?>\n<EntityDescriptor ...>"}
              aria-invalid={fieldErrors.idpMetadataXml ? "true" : undefined}
              style={{ width: "100%", fontFamily: "monospace" }}
            />
            {fieldErrors.idpMetadataXml ? (
              <p className="field-error">{fieldErrors.idpMetadataXml}</p>
            ) : null}
          </>
        )}
      </fieldset>

      <div className="page-actions">
        <button type="submit" className="btn" disabled={busy || envDisabled} aria-busy={busy}>
          {busy ? "Saving…" : submitLabel}
        </button>
        <a className="btn" href={cancelHref}>
          Cancel
        </a>
      </div>
    </form>
  );
}
