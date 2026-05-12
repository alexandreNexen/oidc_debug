function decodeBase64(value) {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

async function copyToClipboard(text, button) {
  if (!text) {
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    if (!button) {
      return;
    }

    const previousContent = button.innerHTML;
    button.innerHTML = '<img src="/assets/icons/true.svg" width="16" height="16" alt="Copied" style="display:block">';
    button.classList.add("is-copied");
    setTimeout(() => {
      button.innerHTML = previousContent;
      button.classList.remove("is-copied");
    }, 1200);
  } catch {
    if (button) {
      button.textContent = "Copy failed";
    }
  }
}

function setupCopyButtons() {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", () => {
      copyToClipboard(button.dataset.copy || "", button);
    });
  });

  document.querySelectorAll("[data-copy-value]").forEach((button) => {
    button.addEventListener("click", () => {
      const text = decodeBase64(button.dataset.copyValue || "");
      copyToClipboard(text, button);
    });
  });
}

function setupConfirmForms() {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.dataset.confirm || "Confirm this action?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
}

function setupRawModal() {
  const modal = document.querySelector("[data-raw-modal]");
  if (!modal) {
    return;
  }

  const title = modal.querySelector("#raw-modal-title");
  const subtitle = modal.querySelector("[data-raw-modal-subtitle]");
  const body = modal.querySelector("[data-raw-modal-body]");
  const copyButton = modal.querySelector("[data-raw-copy]");
  let currentRawText = "";

  const close = () => {
    modal.hidden = true;
    currentRawText = "";
  };

  document.querySelectorAll("[data-raw-close]").forEach((button) => {
    button.addEventListener("click", close);
  });

  modal.addEventListener("click", (event) => {
    if (event.target === modal) {
      close();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modal.hidden) {
      close();
    }
  });

  document.querySelectorAll("[data-raw-open]").forEach((button) => {
    button.addEventListener("click", () => {
      const rawText = decodeBase64(button.dataset.rawJson || "");
      currentRawText = rawText || "No raw data recorded for this step.";

      if (title) {
        title.textContent = button.dataset.rawTitle || "Raw data";
      }

      if (subtitle) {
        const step = button.dataset.rawStep || "";
        const type = button.dataset.rawType || "";
        const nature = button.dataset.rawNature || "";
        subtitle.textContent = [step, type, nature].filter(Boolean).join(" · ");
      }

      if (body) {
        body.textContent = currentRawText;
      }

      modal.hidden = false;
    });
  });

  if (copyButton) {
    copyButton.addEventListener("click", () => {
      copyToClipboard(currentRawText, copyButton);
    });
  }
}

function safeEscapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function updateDiscoveryEndpoints(section, env) {
  const endpointFields = [
    ["issuer", env.issuer],
    ["authorizationEndpoint", env.authorizationEndpoint],
    ["tokenEndpoint", env.tokenEndpoint],
    ["userInfoEndpoint", env.userInfoEndpoint],
    ["jwksUri", env.jwksUri]
  ];

  for (const [field, value] of endpointFields) {
    const el = section.querySelector(`[data-field="${field}"]`);
    if (!el) continue;
    if (value) {
      el.innerHTML = `<code class="code-inline">${safeEscapeHtml(value)}</code>`;
    } else {
      el.innerHTML = `<span class="muted">—</span>`;
    }
  }

  const capFields = [
    ["scopesSupported", env.scopesSupported],
    ["responseTypesSupported", env.responseTypesSupported],
    ["tokenEndpointAuthMethodsSupported", env.tokenEndpointAuthMethodsSupported]
  ];

  let anyCapVisible = false;
  for (const [field, values] of capFields) {
    const row = section.querySelector(`[data-cap-row="${field}"]`);
    if (!row) continue;
    if (Array.isArray(values) && values.length > 0) {
      const valueEl = row.querySelector(`[data-field="${field}"]`);
      if (valueEl) valueEl.textContent = values.join(", ");
      row.hidden = false;
      anyCapVisible = true;
    } else {
      row.hidden = true;
    }
  }

  const capContainer = section.querySelector("[data-cap-container]");
  if (capContainer) {
    capContainer.hidden = !anyCapVisible;
  }
}

function setupDiscoveryForms() {
  document.querySelectorAll("[data-discovery-form]").forEach((form) => {
    const environmentKey = form.dataset.env;
    const input = form.querySelector("[data-discovery-url-input]");
    const button = form.querySelector("[data-discovery-submit]");
    const errorEl = form.querySelector("[data-discovery-error]");
    const endpointsSection = document.querySelector(`[data-discovery-endpoints="${environmentKey}"]`);

    if (!input || !button) return;

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const originalLabel = button.innerHTML;
      button.disabled = true;
      button.textContent = "Importing…";
      if (errorEl) {
        errorEl.textContent = "";
        errorEl.hidden = true;
      }

      try {
        const response = await fetch(`/oidc/discovery/import/${encodeURIComponent(environmentKey)}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ discoveryUrl: input.value.trim() })
        });

        const data = await response.json();

        if (data.ok && endpointsSection) {
          updateDiscoveryEndpoints(endpointsSection, data.environment);
        } else if (errorEl) {
          errorEl.textContent = data.error || "Import failed.";
          errorEl.hidden = false;
        }
      } catch {
        if (errorEl) {
          errorEl.textContent = "Could not reach the server. Please try again.";
          errorEl.hidden = false;
        }
      } finally {
        button.disabled = false;
        button.innerHTML = originalLabel;
      }
    });
  });
}

function setupSectionTabs() {
  document.querySelectorAll("[data-sections-layout]").forEach((layout) => {
    const nav = layout.querySelector("[data-section-nav]");
    if (!nav) return;
    const tabs = Array.from(nav.querySelectorAll("[data-section-tab]"));
    const panels = Array.from(layout.querySelectorAll("[data-section-panel]"));
    if (!tabs.length || !panels.length) return;

    // Hide all panels except the first
    panels.forEach((panel, i) => {
      panel.hidden = i > 0;
    });

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        const id = tab.dataset.sectionTab;

        tabs.forEach((t) => {
          const active = t === tab;
          t.classList.toggle("is-active", active);
          t.setAttribute("aria-selected", active ? "true" : "false");
        });

        panels.forEach((panel) => {
          panel.hidden = panel.dataset.sectionPanel !== id;
        });
      });
    });
  });
}

window.addEventListener("DOMContentLoaded", () => {
  setupCopyButtons();
  setupConfirmForms();
  setupRawModal();
  setupDiscoveryForms();
  setupSectionTabs();
});
