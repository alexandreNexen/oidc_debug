import React, { useCallback, useState } from "react";

// Small button that POSTs a flow action, then navigates the browser to the
// URL returned by the server. The API response is intentionally not stored,
// not logged, and dropped as soon as `redirectUrl` is consumed.
export default function FlowActionButton({
  onAction,
  children,
  className = "btn",
  disabled = false,
  runningLabel = null,
  onError = null,
  title = ""
}) {
  const [state, setState] = useState({ status: "idle", error: "" });

  const handleClick = useCallback(async () => {
    if (state.status === "running") return;
    setState({ status: "running", error: "" });
    try {
      const response = await onAction();
      const redirectUrl = response && typeof response.redirectUrl === "string" ? response.redirectUrl : "";
      if (redirectUrl) {
        window.location.assign(redirectUrl);
        return;
      }
      const message = "Aucune URL de redirection reçue.";
      setState({ status: "error", error: message });
      if (onError) onError(message);
    } catch (error) {
      const message = error && error.message ? error.message : "Action failed.";
      setState({ status: "error", error: message });
      if (onError) onError(message);
    }
  }, [onAction, onError, state.status]);

  const isRunning = state.status === "running";
  const label = isRunning && runningLabel ? runningLabel : children;

  return (
    <>
      <button
        type="button"
        className={className}
        onClick={handleClick}
        disabled={disabled || isRunning}
        aria-busy={isRunning}
        title={title || undefined}
      >
        {label}
      </button>
      {state.status === "error" && !onError ? (
        <span className="muted" role="status" style={{ marginLeft: "0.5rem" }}>
          {state.error}
        </span>
      ) : null}
    </>
  );
}
