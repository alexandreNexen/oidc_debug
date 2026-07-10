import React from "react";

const KNOWN_TONES = new Set(["success", "error", "warning", "neutral", "info"]);

export default function StatusBadge({ label, tone = "neutral" }) {
  const safeTone = KNOWN_TONES.has(tone) ? tone : "neutral";
  const text = label || "—";
  return <span className={`badge badge--${safeTone}`}>{text}</span>;
}
