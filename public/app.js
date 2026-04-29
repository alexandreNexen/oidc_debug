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

    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("is-copied");
    setTimeout(() => {
      button.textContent = previous;
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

function activateTab(tabId) {
  document.querySelectorAll("[data-tab-link]").forEach((link) => {
    link.classList.toggle("is-active", link.dataset.tabLink === tabId);
  });

  document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.tabPanel === tabId);
  });
}

function setupTabs() {
  if (!document.querySelector("[data-tab-link]")) {
    return;
  }

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
        button.textContent = "Show";
        return;
      }

      target.textContent = decodeBase64(target.dataset.actual || "");
      target.dataset.state = "actual";
      button.textContent = "Hide";
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

window.addEventListener("DOMContentLoaded", () => {
  setupCopyButtons();
  setupTabs();
  setupSecretToggles();
  setupConfirmForms();
});
