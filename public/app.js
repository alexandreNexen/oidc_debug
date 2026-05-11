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
        subtitle.textContent = [step, type].filter(Boolean).join(" · ");
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

window.addEventListener("DOMContentLoaded", () => {
  setupCopyButtons();
  setupConfirmForms();
  setupRawModal();
});
