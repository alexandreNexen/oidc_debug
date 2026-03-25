import { redactHeaders, redactObject, toPrettyJson } from "./oidc.js";

function escapeHtml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function pretty(value) {
  if (value === null || value === undefined || value === "") {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  return toPrettyJson(value);
}

function statusClass(kind = "neutral") {
  if (kind === "success") {
    return "status status--success";
  }

  if (kind === "warning") {
    return "status status--warning";
  }

  if (kind === "error") {
    return "status status--error";
  }

  return "status";
}

function encodeData(value) {
  return Buffer.from(String(value), "utf8").toString("base64");
}

function renderPlainBlock(label, value, copyable = false) {
  if (!value) {
    return `
      <div class="kv">
        <span>${escapeHtml(label)}</span>
        <strong>Non disponible</strong>
      </div>
    `;
  }

  const copyButton = copyable
    ? `<button class="ghost-button" type="button" data-copy-value="${escapeHtml(encodeData(value))}" data-copy-label="${escapeHtml(label)}">Copier</button>`
    : "";

  return `
    <div class="data-block">
      <div class="data-block__head">
        <span>${escapeHtml(label)}</span>
        ${copyButton}
      </div>
      <pre>${escapeHtml(value)}</pre>
    </div>
  `;
}

function renderSecretBlock(label, value, copyable = true) {
  if (!value) {
    return `
      <div class="kv">
        <span>${escapeHtml(label)}</span>
        <strong>Non disponible</strong>
      </div>
    `;
  }

  const text = String(value);
  const masked = text.length <= 10 ? "********" : `${text.slice(0, 6)}...${text.slice(-4)}`;
  const blockId = `secret-${encodeData(`${label}-${text.slice(0, 8)}`).replace(/=/g, "")}`;

  return `
    <div class="data-block data-block--secret">
      <div class="data-block__head">
        <span>${escapeHtml(label)}</span>
        <div class="data-block__actions">
          <button class="ghost-button" type="button" data-toggle-secret="${escapeHtml(blockId)}">Afficher</button>
          ${
            copyable
              ? `<button class="ghost-button" type="button" data-copy-value="${escapeHtml(encodeData(text))}" data-copy-label="${escapeHtml(label)}">Copier</button>`
              : ""
          }
        </div>
      </div>
      <pre id="${escapeHtml(blockId)}" data-masked="${escapeHtml(encodeData(masked))}" data-actual="${escapeHtml(encodeData(text))}">${escapeHtml(masked)}</pre>
    </div>
  `;
}

function renderPreCard(title, value, options = {}) {
  const settings = typeof options === "boolean" ? { copyable: options } : options;
  const content = pretty(value);

  if (!content) {
    return `
      <article class="subpanel">
        <header class="subpanel__head">
          <h4>${escapeHtml(title)}</h4>
        </header>
        <p class="empty">Aucune donnee.</p>
      </article>
    `;
  }

  const copyButton = settings.copyable
    ? `<button class="ghost-button" type="button" data-copy-value="${escapeHtml(encodeData(content))}" data-copy-label="${escapeHtml(title)}">Copier</button>`
    : "";

  return `
    <article class="subpanel">
      <header class="subpanel__head">
        <h4>${escapeHtml(title)}</h4>
        ${copyButton}
      </header>
      <pre>${escapeHtml(content)}</pre>
    </article>
  `;
}

function renderRequestResponse(step) {
  if (!step) {
    return `<p class="empty">Aucune execution pour cette etape.</p>`;
  }

  const request = step.request || {};
  const response = step.response || {};
  const statusTone =
    response.status >= 200 && response.status < 300 ? "success" : response.status >= 400 ? "error" : "warning";

  return `
    <div class="grid grid--two">
      <article class="subpanel">
        <header class="subpanel__head">
          <h4>Requete sortante</h4>
          <span class="${statusClass("neutral")}">${escapeHtml(request.method || "GET")}</span>
        </header>
        ${renderPlainBlock("URL", request.url || "", true)}
        ${renderPreCard("Headers", redactHeaders(request.headers || {}))}
        ${renderPreCard("Parametres", request.params && Object.keys(request.params).length ? request.params : null)}
        ${request.body ? renderSecretBlock("Body exact", request.body, true) : `<p class="empty">Aucun body.</p>`}
        ${request.redactedBody ? renderPreCard("Body masque", request.redactedBody) : ""}
        ${request.curl ? renderSecretBlock("curl equivalent", request.curl, true) : ""}
      </article>
      <article class="subpanel">
        <header class="subpanel__head">
          <h4>Reponse entrante</h4>
          ${
            response.status
              ? `<span class="${statusClass(statusTone)}">${escapeHtml(String(response.status))}</span>`
              : `<span class="${statusClass("warning")}">En attente</span>`
          }
        </header>
        ${response.error ? `<div class="flash flash--error">${escapeHtml(response.error)}</div>` : ""}
        ${response.diagnostics ? renderPreCard("Diagnostic reseau", response.diagnostics) : ""}
        ${renderPreCard("Headers", response.headers && Object.keys(response.headers).length ? response.headers : null)}
        ${response.body ? renderSecretBlock("Body brut", response.body, true) : `<p class="empty">Aucun body.</p>`}
        ${response.redactedBody ? renderPreCard("Body masque", response.redactedBody) : ""}
        ${renderPreCard("Body interprete", response.parsed)}
      </article>
    </div>
  `;
}

function renderTokenCard(title, tokenData) {
  if (!tokenData || !tokenData.value) {
    return `
      <article class="subpanel">
        <header class="subpanel__head">
          <h4>${escapeHtml(title)}</h4>
        </header>
        <p class="empty">Token absent.</p>
      </article>
    `;
  }

  const decodedState = tokenData.decoded?.isJwt ? "success" : "warning";

  return `
    <article class="subpanel">
      <header class="subpanel__head">
        <h4>${escapeHtml(title)}</h4>
        <span class="${statusClass(decodedState)}">${escapeHtml(tokenData.format || "opaque")}</span>
      </header>
      ${renderSecretBlock("Valeur brute", tokenData.value)}
      <div class="mini-grid">
        <div class="kv">
          <span>Format</span>
          <strong>${escapeHtml(tokenData.format || "inconnu")}</strong>
        </div>
        <div class="kv">
          <span>Expiration</span>
          <strong>${escapeHtml(tokenData.expiration?.iso || "Non lisible")}</strong>
        </div>
      </div>
      ${renderPreCard("Header JWT", tokenData.decoded?.header || null)}
      ${renderPreCard("Payload JWT", tokenData.decoded?.payload || null)}
      ${tokenData.decoded?.error ? `<div class="flash flash--warning">${escapeHtml(tokenData.decoded.error)}</div>` : ""}
    </article>
  `;
}

function renderComparison(comparison) {
  if (!comparison) {
    return `<p class="empty">Aucune comparaison disponible.</p>`;
  }

  return `
    <div class="grid grid--three">
      ${renderPreCard("Claims uniquement dans id_token", comparison.onlyInIdToken || [])}
      ${renderPreCard("Claims uniquement dans userinfo", comparison.onlyInUserInfo || [])}
      ${renderPreCard("Claims differents", comparison.differing || [])}
    </div>
  `;
}

function renderLogs(logs = []) {
  if (!logs.length) {
    return `<p class="empty">Aucun evenement journalise pour cette session.</p>`;
  }

  return logs
    .map((entry) => {
      const details = pretty(entry.data);
      return `
        <article class="log-entry">
          <div class="log-entry__meta">
            <span class="${statusClass(entry.level === "error" ? "error" : entry.level === "warn" ? "warning" : "success")}">${escapeHtml(entry.level.toUpperCase())}</span>
            <strong>${escapeHtml(entry.event)}</strong>
            <time>${escapeHtml(new Date(entry.time).toLocaleString("fr-FR"))}</time>
          </div>
          <p>${escapeHtml(entry.message)}</p>
          ${details ? `<details><summary>Donnees redigees</summary><pre>${escapeHtml(details)}</pre></details>` : ""}
        </article>
      `;
    })
    .join("");
}

function renderFlash(flash) {
  if (!flash) {
    return "";
  }

  const kind = flash.level === "error" ? "error" : flash.level === "warn" ? "warning" : "success";
  return `<div class="flash flash--${kind}">${escapeHtml(flash.message)}</div>`;
}

function renderInput(label, name, value, options = {}) {
  const type = options.type || "text";
  const placeholder = options.placeholder || "";
  const help = options.help || "";
  const required = options.required ? "required" : "";
  const disabled = options.disabled ? "disabled" : "";
  const readonly = options.readonly ? "readonly" : "";
  const inputClass = options.long ? "field field--wide" : "field";

  return `
    <label class="${inputClass}">
      <span>${escapeHtml(label)}</span>
      <input type="${escapeHtml(type)}" name="${escapeHtml(name)}" value="${escapeHtml(value || "")}" placeholder="${escapeHtml(placeholder)}" ${required} ${disabled} ${readonly} />
      ${help ? `<small>${escapeHtml(help)}</small>` : ""}
    </label>
  `;
}

function renderSelect(label, name, value, entries) {
  return `
    <label class="field">
      <span>${escapeHtml(label)}</span>
      <select name="${escapeHtml(name)}">
        ${entries
          .map(
            ([optionValue, optionLabel]) =>
              `<option value="${escapeHtml(optionValue)}" ${value === optionValue ? "selected" : ""}>${escapeHtml(optionLabel)}</option>`
          )
          .join("")}
      </select>
    </label>
  `;
}

function callbackStatus(callback) {
  const stateCheck = callback?.stateCheck || "unknown";

  if (stateCheck === "match") {
    return {
      kind: "success",
      label: "state valide"
    };
  }

  if (stateCheck === "mismatch") {
    return {
      kind: "error",
      label: "state mismatch"
    };
  }

  if (stateCheck === "missing") {
    return {
      kind: "warning",
      label: "state absent"
    };
  }

  return {
    kind: "warning",
    label: "state non verifie"
  };
}

function summaryCards(session, providerConfig, selectedServiceProvider) {
  const authorizeReady = Boolean(session.steps.authorize?.request?.url);
  const callbackReceived = Boolean(session.steps.callback?.params);
  const tokenResponse = session.steps.token?.response?.status;
  const providerReady = Boolean(providerConfig.discoveryUrl || (providerConfig.authorizationEndpoint && providerConfig.tokenEndpoint));

  const cards = [
    {
      label: "Provider",
      value: providerConfig.providerName || "Non defini",
      kind: providerReady ? "success" : "warning"
    },
    {
      label: "SP selectionne",
      value: selectedServiceProvider?.name || selectedServiceProvider?.clientId || "Aucun",
      kind: selectedServiceProvider ? "success" : "warning"
    },
    {
      label: "Authorize",
      value: authorizeReady ? "Pret" : "A lancer",
      kind: authorizeReady ? "success" : "warning"
    },
    {
      label: "Token",
      value: tokenResponse ? `${tokenResponse}` : callbackReceived ? "En attente" : "Non lance",
      kind: tokenResponse >= 200 && tokenResponse < 300 ? "success" : tokenResponse >= 400 ? "error" : "warning"
    }
  ];

  return cards
    .map(
      (card) => `
        <article class="summary-card">
          <span>${escapeHtml(card.label)}</span>
          <strong>${escapeHtml(card.value)}</strong>
          <span class="${statusClass(card.kind)}"></span>
        </article>
      `
    )
    .join("");
}

function renderReadonlyPair(label, value, tone = "success") {
  return `
    <div class="readonly-item">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value || "Non defini")}</strong>
      <em class="${statusClass(tone)}"></em>
    </div>
  `;
}

function renderServiceProviderRows(serviceProviders, selectedServiceProvider) {
  if (!serviceProviders.length) {
    return `<p class="empty">Aucun Service Provider configure.</p>`;
  }

  return `
    <div class="sp-list">
      ${serviceProviders
        .map((serviceProvider) => {
          const selected = selectedServiceProvider?.id === serviceProvider.id;
          const secretStatus = serviceProvider.clientType === "confidential"
            ? serviceProvider.secretConfigured
              ? "Secret configure"
              : "Aucun secret configure"
            : "Non requis";
          const secretTone = serviceProvider.clientType === "confidential"
            ? serviceProvider.secretConfigured
              ? "success"
              : "warning"
            : "success";

          return `
            <article class="sp-row ${selected ? "sp-row--selected" : ""}">
              <div class="sp-row__identity">
                <strong>${escapeHtml(serviceProvider.name || serviceProvider.clientId || "Sans nom")}</strong>
                <span>${escapeHtml(serviceProvider.clientId || "client_id manquant")}</span>
              </div>
              <div class="sp-row__meta">
                <span class="${statusClass(selected ? "success" : "neutral")}">${selected ? "Selectionne" : "Disponible"}</span>
                <span class="${statusClass(serviceProvider.clientType === "confidential" ? "success" : "warning")}">${escapeHtml(serviceProvider.clientType)}</span>
                <span class="${statusClass(secretTone)}">${escapeHtml(secretStatus)}</span>
              </div>
              <div class="sp-row__actions">
                <form method="post" action="/service-providers/select">
                  <input type="hidden" name="id" value="${escapeHtml(serviceProvider.id)}" />
                  <button class="ghost-button" type="submit">Selectionner</button>
                </form>
                <a class="ghost-button" href="/?tab=configuration&edit=${escapeHtml(serviceProvider.id)}">Editer</a>
                <form method="post" action="/service-providers/delete" onsubmit="return confirm('Supprimer ce Service Provider ?');">
                  <input type="hidden" name="id" value="${escapeHtml(serviceProvider.id)}" />
                  <button class="ghost-button" type="submit">Supprimer</button>
                </form>
                <form method="post" action="/service-providers/test">
                  <input type="hidden" name="id" value="${escapeHtml(serviceProvider.id)}" />
                  <button class="primary-button" type="submit">Tester</button>
                </form>
              </div>
            </article>
          `;
        })
        .join("")}
    </div>
  `;
}

function renderServiceProviderForm(editingServiceProvider, selectedServiceProvider, fixedRedirectUri) {
  const model = editingServiceProvider || {
    id: "",
    name: "",
    clientId: "",
    clientType: "confidential",
    scopes: "",
    secretConfigured: false
  };
  const editing = Boolean(editingServiceProvider?.id);
  const secretLabel = model.clientType === "confidential"
    ? model.secretConfigured
      ? "Secret configure"
      : "Aucun secret configure"
    : "Non requis";
  const secretHelp = model.clientType === "confidential"
    ? editing
      ? "Laissez vide pour conserver le secret existant. Saisir une nouvelle valeur le remplacera."
      : "Le secret est stocke uniquement cote serveur et ne sera plus reaffiche."
    : "Les clients publics restent toleres, mais l'application est optimisee pour les clients confidentiels.";

  return `
    <form class="subpanel" method="post" action="/service-providers/save">
      <header class="subpanel__head">
        <h3>${editing ? "Modifier un Service Provider" : "Nouveau Service Provider"}</h3>
        ${
          editing
            ? `<a class="ghost-button" href="/?tab=configuration">Nouveau</a>`
            : ""
        }
      </header>
      <input type="hidden" name="id" value="${escapeHtml(model.id || "")}" />
      <div class="form-grid">
        ${renderInput("Nom", "name", model.name, {
          required: true
        })}
        ${renderInput("Client ID", "clientId", model.clientId, {
          required: true
        })}
        ${renderSelect("Client type", "clientType", model.clientType, [
          ["confidential", "Confidential"],
          ["public", "Public"]
        ])}
        ${renderInput("Scopes", "scopes", model.scopes || "", {
          long: true,
          help: "Scopes OIDC envoyes pour ce Service Provider. Exemple: openid profile email offline_access"
        })}
        ${renderInput(
          editing && model.secretConfigured ? "Remplacer le secret client" : "Client secret",
          "clientSecret",
          "",
          {
            type: "password",
            help: `${secretLabel}. ${secretHelp}`,
            long: true
          }
        )}
      </div>
      <div class="readonly-grid">
        ${renderReadonlyPair("Redirect URI globale", fixedRedirectUri)}
        ${renderReadonlyPair("Auth /token", model.clientType === "confidential" ? "client_secret_basic" : "none", model.clientType === "confidential" ? "success" : "warning")}
        ${renderReadonlyPair("Response type", "code")}
        ${renderReadonlyPair("Gestion runtime", "state, nonce et PKCE automatiques")}
        ${renderReadonlyPair("Scopes", model.scopes || "Aucun")}
        ${renderReadonlyPair("SP actuellement selectionne", selectedServiceProvider?.name || selectedServiceProvider?.clientId || "Aucun", selectedServiceProvider ? "success" : "warning")}
      </div>
      <div class="form-actions">
        <button type="submit" class="secondary-button" name="_action" value="save">Enregistrer</button>
        <button type="submit" class="primary-button" name="_action" value="saveAndTest">Enregistrer et tester</button>
      </div>
    </form>
  `;
}

export function renderPage({
  session,
  activeTab = "configuration",
  flash = null,
  providerConfig,
  serviceProviders,
  editingServiceProvider,
  selectedServiceProvider,
  fixedRedirectUri
}) {
  const callback = session.steps.callback;
  const callbackBadge = callbackStatus(callback);
  const sessionJsonUrl = `/oidc/session/${encodeURIComponent(session.id)}`;
  const redactedSnapshot = {
    providerConfig,
    selectedServiceProvider,
    runtimeContext: session.runtimeContext,
    steps: redactObject(session.steps),
    tokens: redactObject(session.tokens)
  };

  return `<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>oidc_debug</title>
    <link rel="stylesheet" href="/assets/app.css" />
  </head>
  <body data-active-tab="${escapeHtml(activeTab)}">
    <div class="background-glow"></div>
    <div class="shell">
      <section class="summary">
        ${summaryCards(session, providerConfig, selectedServiceProvider)}
      </section>

      ${renderFlash(flash)}

      <nav class="tabbar" aria-label="Sections techniques">
        <a href="#configuration" data-tab-link="configuration">Configuration</a>
        <a href="#authorize" data-tab-link="authorize">Authorize</a>
        <a href="#callback" data-tab-link="callback">Callback</a>
        <a href="#token" data-tab-link="token">Token</a>
        <a href="#decoded" data-tab-link="decoded">Tokens decodes</a>
        <a href="#userinfo" data-tab-link="userinfo">UserInfo</a>
        <a href="#logs" data-tab-link="logs">Logs</a>
      </nav>

      <main class="sections">
        <section id="configuration" class="panel" data-tab-panel="configuration">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 1</p>
              <h2>Configuration provider et Service Providers</h2>
              <p class="panel__lead">Une seule configuration provider globale, plusieurs SP reutilisables, et une redirect URI fixe pour tous les tests.</p>
            </div>
            <span class="${statusClass(selectedServiceProvider ? "success" : "warning")}">${selectedServiceProvider ? "SP pret" : "SP requis"}</span>
          </div>

          <div class="stack stack--lg">
            <div class="grid grid--two">
              <form class="subpanel" method="post" action="/provider/save">
                <header class="subpanel__head">
                  <h3>Configuration provider globale</h3>
                </header>
                <div class="form-grid">
                  ${renderInput("Nom du provider", "providerName", providerConfig.providerName)}
                  ${renderInput("Redirect URI globale", "redirectUri", fixedRedirectUri, {
                    long: true,
                    help: "Cette valeur doit correspondre exactement a la redirect URI enregistree cote EZ-ACCESS."
                  })}
                </div>
                <div class="form-actions">
                  <button type="submit" class="secondary-button">Enregistrer le provider</button>
                </div>
              </form>

              <div class="subpanel">
                <header class="subpanel__head">
                  <h3>Import Discovery</h3>
                </header>
                <form method="post" action="/provider/load-discovery" class="stack">
                  ${renderInput("Discovery URL", "discoveryUrl", providerConfig.discoveryUrl, {
                    placeholder: "https://idp/.well-known/openid-configuration",
                    long: true
                  })}
                  <div class="form-actions">
                    <button type="submit" class="ghost-button">Verifier le well-known</button>
                  </div>
                </form>
                <p class="note">Le well-known est conserve comme source de verite. Les endpoints sont resolus au moment du test et ne sont plus affiches ici.</p>
              </div>
            </div>

            <div class="subpanel">
              <header class="subpanel__head">
                <h3>Liste des Service Providers</h3>
                <span class="${statusClass(serviceProviders.length ? "success" : "warning")}">${escapeHtml(String(serviceProviders.length))} configuration(s)</span>
              </header>
              ${renderServiceProviderRows(serviceProviders, selectedServiceProvider)}
            </div>

            ${renderServiceProviderForm(editingServiceProvider, selectedServiceProvider, fixedRedirectUri)}

            <div class="subpanel">
              <header class="subpanel__head">
                <h3>Snapshot courant</h3>
                <a class="ghost-button" href="${escapeHtml(sessionJsonUrl)}">Exporter JSON</a>
              </header>
              <pre>${escapeHtml(pretty(redactedSnapshot))}</pre>
            </div>
          </div>
        </section>

        <section id="authorize" class="panel" data-tab-panel="authorize">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 2</p>
              <h2>Authorize</h2>
              <div class="form-actions form-actions--head">
                ${
                  selectedServiceProvider
                    ? `<form method="post" action="/service-providers/test">
                        <input type="hidden" name="id" value="${escapeHtml(selectedServiceProvider.id)}" />
                        <button class="primary-button" type="submit">Tester ce SP</button>
                      </form>`
                    : `<a class="ghost-button" href="#configuration" data-tab-link="configuration">Choisir un SP</a>`
                }
              </div>
            </div>
            <span class="${statusClass(session.steps.authorize?.request?.url ? "success" : "warning")}">
              ${session.steps.authorize?.request?.url ? "Pret" : "Non prepare"}
            </span>
          </div>
          <div class="subpanel">
            <header class="subpanel__head">
              <h3>Construction de l'URL /authorize</h3>
            </header>
            ${renderRequestResponse(session.steps.authorize)}
            ${
              session.runtimeContext
                ? `
                  <div class="readonly-grid">
                    ${renderReadonlyPair("Provider", session.runtimeContext.providerName || "Non defini")}
                    ${renderReadonlyPair("Service Provider", session.runtimeContext.serviceProviderName || session.runtimeContext.clientId)}
                    ${renderReadonlyPair("Client ID", session.runtimeContext.clientId)}
                    ${renderReadonlyPair("Redirect URI", session.runtimeContext.redirectUri)}
                    ${renderReadonlyPair("Auth /token", session.runtimeContext.tokenEndpointAuthMethod)}
                    ${renderReadonlyPair("Client type", session.runtimeContext.clientType)}
                  </div>
                `
                : ""
            }
            ${
              session.flow.expectedState || session.flow.codeVerifier
                ? `
                  <div class="grid grid--two">
                    ${renderPreCard(
                      "Contexte runtime",
                      {
                        state: session.flow.expectedState || null,
                        nonce: session.flow.expectedNonce || null,
                        codeChallenge: session.flow.codeChallenge || null
                      },
                      { copyable: true }
                    )}
                    ${
                      session.flow.codeVerifier
                        ? renderSecretBlock("PKCE code_verifier", session.flow.codeVerifier, true)
                        : `<p class="empty">PKCE indisponible.</p>`
                    }
                  </div>
                `
                : ""
            }
          </div>
        </section>

        <section id="callback" class="panel" data-tab-panel="callback">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 3</p>
              <h2>Callback OIDC</h2>
              <div class="form-actions form-actions--head">
                <button type="submit" class="primary-button" form="token-exchange-form">Echanger le code</button>
              </div>
            </div>
            <span class="${statusClass(callbackBadge.kind)}">${escapeHtml(callbackBadge.label)}</span>
          </div>
          <div class="grid grid--two">
            <div class="subpanel">
              <header class="subpanel__head">
                <h3>Parametres recus</h3>
              </header>
              ${callback?.params ? renderPreCard("Callback brut", callback.params, { copyable: true }) : `<p class="empty">Aucun callback recu.</p>`}
              ${callback?.raw ? renderPreCard("Payload brut", callback.raw, true) : ""}
            </div>
            <div class="subpanel">
              <header class="subpanel__head">
                <h3>Interpretation</h3>
              </header>
              ${renderPreCard(
                "Lecture fonctionnelle",
                callback
                  ? {
                      method: callback.method,
                      stateCheck: callback.stateCheck,
                      codePresent: Boolean(callback.params?.code),
                      error: callback.params?.error || null
                    }
                  : null
              )}
              <form id="token-exchange-form" method="post" action="/oidc/token/exchange" class="stack">
                ${renderInput("Authorization code", "code", callback?.params?.code || "", {
                  long: true
                })}
              </form>
            </div>
          </div>
        </section>

        <section id="token" class="panel" data-tab-panel="token">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 4</p>
              <h2>Token Endpoint</h2>
            </div>
            <span class="${statusClass(
              session.steps.token?.response?.status >= 200 && session.steps.token?.response?.status < 300
                ? "success"
                : session.steps.token?.response?.status >= 400
                  ? "error"
                  : "warning"
            )}">
              ${escapeHtml(String(session.steps.token?.response?.status || "En attente"))}
            </span>
          </div>
          <div class="subpanel">
            <header class="subpanel__head">
              <h3>Requete /token et reponse</h3>
            </header>
            ${renderRequestResponse(session.steps.token)}
          </div>
        </section>

        <section id="decoded" class="panel" data-tab-panel="decoded">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 5</p>
              <h2>Tokens decodes</h2>
            </div>
            <span class="${statusClass(session.tokens?.idToken?.value ? "success" : "warning")}">
              ${session.tokens?.idToken?.value ? "Disponibles" : "Indisponibles"}
            </span>
          </div>
          <div class="grid grid--two">
            ${renderTokenCard("Access Token", session.tokens?.accessToken)}
            ${renderTokenCard("ID Token", session.tokens?.idToken)}
          </div>
        </section>

        <section id="userinfo" class="panel" data-tab-panel="userinfo">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 6</p>
              <h2>UserInfo</h2>
              <div class="form-actions form-actions--head">
                <button type="submit" class="primary-button" form="userinfo-form">Appeler UserInfo</button>
              </div>
            </div>
            <span class="${statusClass(
              session.steps.userinfo?.response?.status >= 200 && session.steps.userinfo?.response?.status < 300
                ? "success"
                : session.steps.userinfo?.response?.status >= 400
                  ? "error"
                  : "warning"
            )}">
              ${escapeHtml(String(session.steps.userinfo?.response?.status || "Non execute"))}
            </span>
          </div>
          <div class="subpanel">
            <header class="subpanel__head">
              <h3>Appel /userinfo</h3>
            </header>
            <form id="userinfo-form" method="post" action="/oidc/userinfo"></form>
            ${renderRequestResponse(session.steps.userinfo)}
          </div>
          <div class="subpanel">
            <header class="subpanel__head">
              <h3>Comparaison id_token vs userinfo</h3>
            </header>
            ${renderComparison(session.comparison)}
          </div>
        </section>

        <section id="logs" class="panel" data-tab-panel="logs">
          <div class="panel__head">
            <div>
              <p class="eyebrow">Section 7</p>
              <h2>Journal d'execution</h2>
            </div>
            <span class="${statusClass("success")}">${escapeHtml(String(session.logs.length))} evenements</span>
          </div>
          <div class="subpanel">
            <header class="subpanel__head">
              <h3>Timeline</h3>
              <a class="ghost-button" href="${escapeHtml(sessionJsonUrl)}">Exporter JSON</a>
            </header>
            <div class="log-list">
              ${renderLogs(session.logs)}
            </div>
          </div>
        </section>
      </main>
    </div>
    <script src="/assets/app.js" defer></script>
  </body>
</html>`;
}
