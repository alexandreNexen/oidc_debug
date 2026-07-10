import React from "react";
import FlowStepDetail from "./FlowStepDetail.jsx";

export default function FlowStepList({ steps }) {
  const list = Array.isArray(steps) ? steps : [];
  if (list.length === 0) {
    return <p className="muted empty">No step recorded for this flow.</p>;
  }
  return (
    <div className="step-list">
      {list.map((step) => (
        <FlowStepDetail key={step.stepName || Math.random()} step={step} />
      ))}
    </div>
  );
}
