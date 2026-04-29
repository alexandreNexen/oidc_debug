import { renderFlash, renderLayout, renderPageHeader } from "./layout.js";

export function renderLogsPage({ flash } = {}) {
  const body = `
    ${renderFlash(flash)}
    ${renderPageHeader({
      title: "Logs",
      description: "Global and Service Provider logs will be available after persistence is implemented."
    })}

    <section class="card">
      <div class="card__body card__body--centered">
        <div class="empty-state">
          <p class="empty-state__title">No logs available yet.</p>
          <p class="empty-state__hint muted">Global and Service Provider logs will be displayed here in a later release.</p>
        </div>
      </div>
    </section>
  `;

  return renderLayout({
    title: "Logs — Ez-Access OIDC Debug",
    activeNav: "logs",
    body
  });
}
