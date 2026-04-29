export function escapeHtml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderFlash(flash) {
  if (!flash) {
    return "";
  }

  const tone = flash.level === "error" ? "error" : flash.level === "warn" ? "warning" : "info";
  return `<div class="flash flash--${tone}" role="status">${escapeHtml(flash.message)}</div>`;
}

export function renderPageHeader({ title, description = "", actions = "" }) {
  return `
    <header class="page-header">
      <div class="page-header__main">
        <h1 class="page-header__title">${escapeHtml(title)}</h1>
        ${description ? `<p class="page-header__description muted">${escapeHtml(description)}</p>` : ""}
      </div>
      ${actions ? `<div class="page-header__actions">${actions}</div>` : ""}
    </header>
  `;
}

function renderTopbar(activeNav) {
  const navItems = [
    { id: "dashboard", label: "Dashboard", href: "/" },
    { id: "service-providers", label: "Service Providers", href: "/service-providers" }
  ];

  const navHtml = navItems
    .map(
      (item) =>
        `<a class="topbar__link${item.id === activeNav ? " topbar__link--active" : ""}" href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a>`
    )
    .join("");

  return `
    <header class="topbar">
      <div class="topbar__inner">
        <div class="topbar__brand">
          <span class="topbar__title">Ez-Access OIDC Debug Console</span>
        </div>
        <nav class="topbar__nav" aria-label="Navigation principale">${navHtml}</nav>
      </div>
    </header>
  `;
}

export function renderLayout({ title = "Ez-Access OIDC Debug", activeNav = "dashboard", body = "" }) {
  return `<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <link rel="stylesheet" href="/assets/app.css" />
  </head>
  <body class="page">
    ${renderTopbar(activeNav)}
    <main class="shell">
      ${body}
    </main>
    <script src="/assets/app.js" defer></script>
  </body>
</html>`;
}
