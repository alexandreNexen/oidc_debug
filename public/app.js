function decodeBase64(value) {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

async function copyText(base64Value, label, button) {
  const text = decodeBase64(base64Value);
  if (!text) {
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    const previous = button.textContent;
    button.textContent = `${label} copie`;
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  } catch {
    button.textContent = "Copie impossible";
  }
}

function activateTab(tabId) {
  document.querySelectorAll("[data-tab-link]").forEach((link) => {
    link.classList.toggle("is-active", link.dataset.tabLink === tabId);
  });

  document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.tabPanel === tabId);
  });
}

function setupTabs() {
  const initial = window.location.hash.replace("#", "") || document.body.dataset.activeTab || "configuration";
  activateTab(initial);

  document.querySelectorAll("[data-tab-link]").forEach((link) => {
    link.addEventListener("click", (event) => {
      const tabId = link.dataset.tabLink;
      if (!tabId) {
        return;
      }

      event.preventDefault();
      history.replaceState(null, "", `#${tabId}`);
      activateTab(tabId);
    });
  });
}

function setupCopyButtons() {
  document.querySelectorAll("[data-copy-value]").forEach((button) => {
    button.addEventListener("click", () => {
      copyText(button.dataset.copyValue || "", button.dataset.copyLabel || "Valeur", button);
    });
  });
}

function setupSecretToggles() {
  document.querySelectorAll("[data-toggle-secret]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.toggleSecret || "");
      if (!target) {
        return;
      }

      const showingActual = target.dataset.state === "actual";
      if (showingActual) {
        target.textContent = decodeBase64(target.dataset.masked || "");
        target.dataset.state = "masked";
        button.textContent = "Afficher";
        return;
      }

      target.textContent = decodeBase64(target.dataset.actual || "");
      target.dataset.state = "actual";
      button.textContent = "Masquer";
    });
  });
}

window.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupCopyButtons();
  setupSecretToggles();
});
