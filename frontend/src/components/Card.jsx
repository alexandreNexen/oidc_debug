import React from "react";

export default function Card({ title, subtitle = "", actions = null, children }) {
  return (
    <section className="card">
      <header className="card-header">
        <div>
          <h2 className="card-title">{title}</h2>
          {subtitle ? <p className="card-subtitle muted">{subtitle}</p> : null}
        </div>
        {actions ? <div className="card-actions">{actions}</div> : null}
      </header>
      <div className="card-body">{children}</div>
    </section>
  );
}
