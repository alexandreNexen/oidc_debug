import React, { useCallback, useEffect, useRef } from "react";

// Minimal confirmation dialog. Rendered inline (no portal, no dependency).
// The dialog is only mounted when `open` is true; when it opens, the
// confirm button receives focus, and Escape triggers cancel.
//
// Deliberately no localStorage / no cookie / no logging.
export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  busy = false,
  danger = false,
  error = "",
  onConfirm,
  onCancel
}) {
  const confirmRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement;
    if (confirmRef.current) {
      confirmRef.current.focus();
    }
    const onKeyDown = (event) => {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onCancel();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      if (previous && typeof previous.focus === "function") {
        previous.focus();
      }
    };
  }, [open, busy, onCancel]);

  const handleBackdropClick = useCallback(
    (event) => {
      if (event.target === event.currentTarget && !busy) {
        onCancel();
      }
    },
    [busy, onCancel]
  );

  if (!open) return null;

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
      onClick={handleBackdropClick}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000
      }}
    >
      <div
        className="modal"
        style={{
          background: "var(--color-surface, #fff)",
          color: "var(--color-text, #111)",
          borderRadius: "8px",
          padding: "1.5rem",
          maxWidth: "420px",
          width: "min(90vw, 420px)",
          boxShadow: "0 12px 32px rgba(0, 0, 0, 0.25)"
        }}
      >
        <h2 id="confirm-dialog-title" style={{ marginTop: 0 }}>
          {title}
        </h2>
        <p>{message}</p>
        {error ? (
          <p className="alert alert--error" role="alert" style={{ marginTop: "0.75rem" }}>
            {error}
          </p>
        ) : null}
        <div className="page-actions" style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end", marginTop: "1rem" }}>
          <button type="button" className="btn" onClick={onCancel} disabled={busy}>
            {cancelLabel}
          </button>
          <button
            type="button"
            ref={confirmRef}
            className={danger ? "btn btn--danger" : "btn"}
            onClick={onConfirm}
            disabled={busy}
            aria-busy={busy}
          >
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
