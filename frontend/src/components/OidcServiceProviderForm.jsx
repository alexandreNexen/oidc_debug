import React, { useCallback, useEffect, useState } from "react";
import { getOidcEnvironments } from "../api/client.js";

// Shared OIDC Service Provider form used by the new and edit Vite pages.
//
// - The client_secret input is intentionally kept as an uncontrolled password
//   field (React `defaultValue=""` and read from FormData at submit time)
//   so the secret is never written to component state or props.
// - In edit mode, the existing secret is NEVER re-injected: the form only
//   shows a `secretConfigured` badge and lets the user optionally supply a
//   replacement.
// - On success the caller decides where to navigate; this component just
//   returns the API response through `onSubmit`.
export default function OidcServiceProviderForm({
  mode,
  initial = null,
  secretConfigured = false,
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
  const [clientId, setClientId] = useState(initial?.clientId || "");
  const [scopes, setScopes] = useState(initial?.scopes || "");
  const [environment, setEnvironment] = useState(initial?.environment || "");

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

      const form = event.currentTarget;
      const data = new FormData(form);
      const rawSecret = String(data.get("client_secret") || "");
      const payload = {
        name: String(data.get("name") || "").trim(),
        environment: String(data.get("environment") || "").trim(),
        clientId: String(data.get("client_id") || "").trim(),
        scopes: String(data.get("scopes") || "").trim()
      };
      if (rawSecret) {
        payload.clientSecret = rawSecret;
      }

      setBusy(true);
      setFormError("");
      setFieldErrors({});
      setWarnings([]);

      try {
        const response = await onSubmit(payload);
        // Clear the password input as soon as the request settles.
        const secretInput = form.querySelector('input[name="client_secret"]');
        if (secretInput) secretInput.value = "";
        if (response && Array.isArray(response.warnings)) {
          setWarnings(response.warnings);
        }
        const redirectUrl = response && typeof response.redirectUrl === "string" ? response.redirectUrl : "";
        if (redirectUrl) {
          window.location.assign(redirectUrl);
          return;
        }
      } catch (error) {
        // Belt-and-suspenders: also clear the password field on error so a
        // shoulder-surfer can't rebind it.
        const secretInput = form.querySelector('input[name="client_secret"]');
        if (secretInput) secretInput.value = "";
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
    [busy, onSubmit]
  );

  const envDisabled = envState.status !== "ready" || busy;
  const secretLabel = mode === "edit" ? "Client Secret (leave blank to keep existing)" : "Client Secret";
  const secretPlaceholder = mode === "edit" ? "Leave blank to keep existing secret" : "";

  return (
    <form className="sp-form" onSubmit={handleSubmit} noValidate>
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
        {envState.status === "error" ? (
          <p className="field-error">{envState.error}</p>
        ) : null}
        {fieldErrors.environment ? <p className="field-error">{fieldErrors.environment}</p> : null}
      </div>

      <div className="sp-form__field">
        <label htmlFor="field-client_id">Client ID</label>
        <input
          id="field-client_id"
          name="client_id"
          type="text"
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          required
          aria-invalid={fieldErrors.client_id ? "true" : undefined}
        />
        {fieldErrors.client_id ? <p className="field-error">{fieldErrors.client_id}</p> : null}
      </div>

      <div className="sp-form__field">
        <label htmlFor="field-client_secret">{secretLabel}</label>
        {mode === "edit" ? (
          <p className="muted" style={{ marginBottom: "0.25rem" }}>
            Secret status:{" "}
            <span className={`badge badge--${secretConfigured ? "success" : "warning"}`}>
              {secretConfigured ? "configured" : "not configured"}
            </span>
          </p>
        ) : null}
        <input
          id="field-client_secret"
          name="client_secret"
          type="password"
          defaultValue=""
          autoComplete="new-password"
          placeholder={secretPlaceholder}
          required={mode === "create"}
          aria-invalid={fieldErrors.client_secret ? "true" : undefined}
        />
        {fieldErrors.client_secret ? <p className="field-error">{fieldErrors.client_secret}</p> : null}
      </div>

      <div className="sp-form__field">
        <label htmlFor="field-scopes">Scopes</label>
        <input
          id="field-scopes"
          name="scopes"
          type="text"
          value={scopes}
          onChange={(e) => setScopes(e.target.value)}
          placeholder="openid"
          required
          aria-invalid={fieldErrors.scopes ? "true" : undefined}
        />
        <p className="muted">Required scope: openid</p>
        {fieldErrors.scopes ? <p className="field-error">{fieldErrors.scopes}</p> : null}
      </div>

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
