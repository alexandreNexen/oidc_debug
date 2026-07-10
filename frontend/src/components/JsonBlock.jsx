import React, { useState } from "react";

const COLLAPSED_MAX_LINES = 12;

function stringify(value) {
  if (value === null || value === undefined) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export default function JsonBlock({ value, label = "", defaultExpanded = false }) {
  const text = stringify(value);
  const lineCount = text ? text.split("\n").length : 0;
  const canCollapse = lineCount > COLLAPSED_MAX_LINES;
  const [expanded, setExpanded] = useState(defaultExpanded || !canCollapse);

  if (!text) {
    return (
      <div className="json-block json-block--empty">
        {label ? <div className="json-block-label muted">{label}</div> : null}
        <p className="muted empty">No data.</p>
      </div>
    );
  }

  const displayText = expanded ? text : text.split("\n").slice(0, COLLAPSED_MAX_LINES).join("\n");

  return (
    <div className="json-block">
      {label ? <div className="json-block-label muted">{label}</div> : null}
      <pre className="json-body">{displayText}</pre>
      {canCollapse ? (
        <button
          type="button"
          className="btn btn--small json-toggle"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
        >
          {expanded ? "Collapse" : `Show ${lineCount - COLLAPSED_MAX_LINES} more line(s)`}
        </button>
      ) : null}
    </div>
  );
}
