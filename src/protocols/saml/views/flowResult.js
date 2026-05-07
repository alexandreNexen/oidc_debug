import { escapeHtml, renderFlash, renderIconBtn, renderLayout, renderPageHeader, renderStatusIcon } from "../../../common/views/layout.js";

function formatDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "Non disponible";
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "En cours";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function resultTitle(status) {
  if (status === "success") return "Flow SAML terminé avec succès";
  if (status === "failed") return "Flow SAML en échec";
  if (status === "partial_success") return "Flow SAML partiellement complété";
  return "Flow SAML en cours";
}

function renderSummaryRow(label, value) {
  return `
    <div class="kv-list__row">
      <dt>${escapeHtml(label)}</dt>
      <dd>${value}</dd>
    </div>
  `;
}

function renderTimeline(steps = []) {
  return `
    <ol class="flow-timeline">
      ${steps
        .map(
          (step) => `
            <li class="flow-timeline__item flow-timeline__item--${escapeHtml(step.badge.tone)}">
              <span class="flow-timeline__dot"></span>
              <span class="flow-timeline__label">${escapeHtml(step.stepName)}</span>
              ${renderStatusIcon(step.badge)}
            </li>
          `
        )
        .join("")}
    </ol>
  `;
}

export function renderSamlFlowResultPage({ flow, serviceProvider, steps = [], flash }) {
  const status = flow.statusBadge || { label: "En cours", tone: "neutral" };
  const failed = flow.status === "failed" || flow.status === "partial_success";
  const detailsHref = `/saml/flows/${encodeURIComponent(flow.id)}/details`;

  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Résultat du flow SAML",
      description: resultTitle(flow.status),
      actions: `<span class="badge badge--${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span>`
    })}

    <section class="card">
      <header class="card-header">
        <h2 class="card-header__title">Résumé</h2>
      </header>
      <div class="card__body">
        <dl class="kv-list">
          ${renderSummaryRow("Service Provider", escapeHtml(serviceProvider.name || "Inconnu"))}
          ${renderSummaryRow("Environment", flow.environmentLabel
            ? `<span class="badge badge--neutral">${escapeHtml(flow.environmentLabel)}</span>`
            : `<span class="badge badge--warning">Environment manquant</span>`
          )}
          ${renderSummaryRow("SP Entity ID", `<code class="code-inline">${escapeHtml(flow.runtime?.spEntityId || "")}</code>`)}
          ${renderSummaryRow("IdP SSO URL", flow.runtime?.ssoUrl
            ? `<code class="code-inline">${escapeHtml(flow.runtime.ssoUrl)}</code>`
            : `<span class="muted">Non disponible</span>`
          )}
          ${renderSummaryRow("IdP Entity ID", flow.runtime?.idpEntityId
            ? `<code class="code-inline">${escapeHtml(flow.runtime.idpEntityId)}</code>`
            : `<span class="muted">Non disponible</span>`
          )}
          ${renderSummaryRow("ACS URL", `<code class="code-inline">${escapeHtml(flow.runtime?.acsUrl || "")}</code>`)}
          ${renderSummaryRow("RelayState", flow.runtime?.relayState ? "Présent" : `<span class="muted">Absent</span>`)}
          ${renderSummaryRow("Démarré à", escapeHtml(formatDate(flow.startedAt)))}
          ${renderSummaryRow("Durée", escapeHtml(formatDuration(flow.durationMs)))}
          ${failed && flow.failedStep ? renderSummaryRow("Étape en échec", `<span class="badge badge--warning">${escapeHtml(flow.failedStep)}</span>`) : ""}
          ${failed && flow.errorCode ? renderSummaryRow("Code erreur", `<code class="code-inline">${escapeHtml(flow.errorCode)}</code>`) : ""}
          ${failed && flow.errorDescription ? renderSummaryRow("Erreur", escapeHtml(flow.errorDescription)) : ""}
        </dl>
      </div>
    </section>

    <section class="card flow-section">
      <header class="card-header">
        <h2 class="card-header__title">Étapes</h2>
      </header>
      <div class="card__body">
        ${renderTimeline(steps)}
      </div>
    </section>

    <div class="flow-actions">
      ${renderIconBtn({ icon: "details", label: "Voir les détails", href: detailsHref, variant: "neutral", showLabel: true })}
      ${renderIconBtn({ icon: "replay", label: "Relancer", href: `/saml/flows/start/${encodeURIComponent(flow.serviceProviderId)}`, variant: "neutral", showLabel: true })}
      ${failed && serviceProvider?.id
        ? renderIconBtn({ icon: "edit", label: "Modifier le Service Provider", href: `/saml/service-providers/${encodeURIComponent(serviceProvider.id)}/edit`, variant: "neutral", showLabel: true })
        : ""}
      ${renderIconBtn({ icon: "return", label: "Retour à la liste", href: "/saml/service-providers", variant: "neutral", showLabel: true })}
    </div>
  `;

  return renderLayout({
    title: "Résultat flow SAML — Ez-Access Debug",
    activeNav: "saml-service-providers",
    body
  });
}
