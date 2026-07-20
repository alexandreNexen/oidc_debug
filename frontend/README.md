# frontend/ — Vite React (frontend principal)

Frontend Vite React, l'interface principale de la console. Alimenté par les
endpoints `/api/*`. La logique OIDC/SAML sensible (callbacks, token
exchange, ACS, signature, sessions, secrets) reste dans `src/server.js`
(backend Node). Le SSR historique a été isolé sous `/legacy/*` (dev-only).

## Deux modes de lancement

### Mode 1 — Dev HMR (deux processus)

```bash
# Terminal 1 — backend Node (API JSON, callbacks IdP, sessions)
npm start                          # ou: npm run dev

# Terminal 2 — frontend Vite (UI + HMR)
npm --prefix frontend install       # une fois
npm --prefix frontend run dev       # ou: npm run dev:frontend depuis la racine
```

Par défaut :
- backend Node : `http://localhost:3000` (port configurable via `PORT`)
- frontend Vite : `http://127.0.0.1:5173`

Le navigateur pointe **uniquement** sur `http://127.0.0.1:5173`. Les routes
SPA (`/`, `/oidc/service-providers`, `/saml/flows/:id`, ...) sont servies
par Vite dev via son fallback HTML par défaut : `frontend/index.html` →
`/src/main.jsx` → React (avec HMR).

Le proxy Vite dev relaie vers le backend Node **uniquement** :

- `/api/*` — API JSON (le seul namespace utilisé par le client React)
- `/favicon.svg`, `/favicon.ico` — favicons servis par le backend

Ne sont **pas** proxyfiés (donc traités localement par Vite dev) :

- `/oidc/*`, `/saml/*` — routes SPA, fallback vers `frontend/index.html`
- `/static/*` — namespace du build production, sans emploi en dev
- `/assets/*`, `/health`, `/legacy/*` — hors périmètre du frontend Vite

Cible du proxy override : `BACKEND_URL=http://localhost:3000` (variable
d'environnement lue par `vite.config.js`).

### Mode 2 — Build intégré (backend seul)

```bash
npm run build:frontend             # produit frontend/dist/ (base /static/)
npm start                          # backend sert la SPA + /api/*
```

Ouvrir `http://localhost:3000`. Vite dev n'est pas lancé — le backend Node
sert `frontend/dist/index.html` sur les routes SPA (allow-list
`isSpaRoute`) et streame `frontend/dist/assets/<hash>.{js,css}` sous
`/static/assets/*`. Aucune HMR : chaque modif front demande un rebuild.

### Symptôme d'une mauvaise configuration

Si en mode dev le navigateur reçoit un 404 sur `/static/assets/index-<hash>.js`,
c'est le signe qu'une route SPA a été proxyfiée vers le backend et que
celui-ci a répondu avec `dist/index.html` (référence `/static/...`). Le
proxy Vite dev doit rester limité à `/api/*` et aux favicons ; sinon la
SPA reçoit un HTML de build qui n'existe pas en dev.

## Pourquoi passer par le proxy ?

- Le navigateur voit une **même origine** (`127.0.0.1:5173`) → le cookie de
  session `HttpOnly; SameSite=Lax` continue de fonctionner sans configuration
  CORS.
- Les callbacks IdP (`/oidc/callback`, `/saml/acs/:spId`) **ne doivent jamais**
  être exposés par Vite : ils sont invoqués par l'IdP externe directement sur
  l'URL publique du backend Node enregistrée chez Ez-Access.

## URL canonique et rôle du proxy

| Cas d'usage | URL à ouvrir dans le navigateur |
| --- | --- |
| Développer l'UI Vite React | `http://127.0.0.1:5173` |
| Tester un vrai flow OIDC/SAML (redirect IdP → callback) | `http://localhost:3000` |
| Callback OIDC enregistré chez l'IdP | `http://localhost:3000/oidc/callback` |
| ACS SAML enregistré chez l'IdP | `http://localhost:3000/saml/acs/:spId` |

Verdict : l'URL Vite est **strictement réservée au développement UI**. Elle ne
doit **jamais** être enregistrée comme `redirect_uri` OIDC ou ACS SAML auprès
d'un IdP. Le backend construit `redirect_uri` et `acsUrl` à partir de
`process.env.BASE_URL` **capturé au démarrage**, jamais à partir des headers de
requête. Pour renforcer cette garantie, le proxy Vite est configuré avec
`xfwd: false` : les en-têtes `X-Forwarded-Host` / `X-Forwarded-Proto` ne sont
volontairement pas transmis au backend, éliminant tout risque futur qu'une
évolution du code lise l'origine depuis la requête.

Pour tester un vrai flow depuis le navigateur en dev, définir
`BASE_URL=http://localhost:3000` dans `.env` (voir `.env.example`), démarrer le
backend, ouvrir `http://localhost:3000` directement (pas Vite).

## Endpoints consommés

Dashboard (synthèse) :

- `GET /api/health`
- `GET /api/oidc/service-providers`
- `GET /api/oidc/flows`
- `GET /api/saml/service-providers`
- `GET /api/saml/flows`

Listes dédiées :

- `/oidc/service-providers` → `GET /api/oidc/service-providers`
- `/saml/service-providers` → `GET /api/saml/service-providers`
- `/oidc/flows` → `GET /api/oidc/flows`
- `/saml/flows` → `GET /api/saml/flows`

Détail OIDC (`/oidc/flows/:id`) :

- `GET /api/oidc/flows/:id`

Détail SAML (`/saml/flows/:id`) :

- `GET /api/saml/flows/:id`

Les pages SSR historiques sont conservées comme **référence dev-only** sous
`/legacy/*` (voir `README.md` racine). Elles sont montées uniquement si
`NODE_ENV !== "production"` ou `ENABLE_LEGACY_SSR=1`, et sont strictement
en lecture seule.

## Routes SPA

Vite est le frontend principal sur les **routes propres sans préfixe** :

- `/` — dashboard.
- `/oidc/service-providers` — liste OIDC.
- `/oidc/service-providers/new` — création OIDC SP.
- `/oidc/service-providers/:id/edit` — édition OIDC SP.
- `/oidc/flows` — liste des flows OIDC.
- `/oidc/flows/:id` — détail OIDC.
- `/saml/service-providers` — liste SAML.
- `/saml/service-providers/new` — création SAML SP.
- `/saml/service-providers/:id/edit` — édition SAML SP.
- `/saml/flows` — liste des flows SAML.
- `/saml/flows/:id` — détail SAML.

Le préfixe `/vite/*` a été **retiré** — il renvoie désormais 404. Le SSR
historique a été isolé sous `/legacy/*` (dev-only ou `ENABLE_LEGACY_SSR=1`).

Le backend Node applique une **allow-list explicite** (`isSpaRoute` dans
`src/server.js`) pour décider quand servir `dist/index.html`. Toute autre URL
— callbacks IdP (`/oidc/callback`, `/saml/acs/:spId`), `/api/*`, `/health`,
`/oidc/flows/start/:spId`, typos — est traitée par le backend et **ne tombe
jamais** sur le SPA.

## Actions applicatives — via `/api/*`

Toute action (create, edit, delete Service Provider, start/rerun flow,
discovery import) passe par les endpoints JSON `/api/*` :

| Action | Endpoint |
| --- | --- |
| Create OIDC SP | `POST /api/oidc/service-providers` |
| Edit OIDC SP | `PATCH /api/oidc/service-providers/:id` |
| Delete OIDC SP | `DELETE /api/oidc/service-providers/:id` |
| Start OIDC flow | `POST /api/oidc/flows/start/:spId` |
| Rerun OIDC flow | `POST /api/oidc/flows/:id/rerun` |
| Import OIDC discovery | `POST /api/oidc/discovery/import/:env` |
| Create SAML SP | `POST /api/saml/service-providers` |
| Edit SAML SP | `PATCH /api/saml/service-providers/:id` |
| Delete SAML SP | `DELETE /api/saml/service-providers/:id` |
| Start SAML flow | `POST /api/saml/flows/start/:spId` |

Les anciennes routes POST canoniques SSR (`POST /oidc/service-providers`,
`POST /oidc/discovery/import/:env`, `POST /oidc/flows/:id/rerun`, etc.)
répondent maintenant **410 Gone** JSON sans effet.

## Valeurs affichées dans le détail OIDC

L'outil est interne, à visée de debug. Le détail affiche les valeurs
**exactes** telles que retournées par l'API — sans transformation
frontend :

- token response, `access_token`/`id_token` bruts si l'API les fournit ;
- claims décodés `id_token` et `access_token` ;
- scopes exacts ;
- introspection response exacte ;
- userinfo response exacte ;
- codes/descriptions d'erreur exactes.

## Valeurs affichées dans le détail SAML

Même politique. Le détail affiche les valeurs exactes reçues de l'API :

- SAMLResponse parsée, assertion, attributs SAML ;
- NameID, sessionIndex, issuer, audience, destination, subjectConfirmation ;
- `response_signature_verification`, `assertion_signature_verification`,
  `signature_verification_result` ;
- `trust_validation` global et checks détaillés ;
- `trust_validation_errors`, `trust_validation_warnings` ;
- codes/descriptions d'erreur exactes.

Aucune clé privée, aucun secret de configuration, aucun contenu brut de
`data/state.json` n'est affiché — ces artefacts ne sont jamais renvoyés par
l'API.

Les artefacts qui ne servent jamais au diagnostic
(`client_secret`, `code_verifier`, `expectedState`/`expectedNonce` en clair,
`SESSION_SECRET`, clés dérivées, contenu brut de `data/state.json`) sont
supprimés par le backend avant que l'API ne les renvoie. Le frontend
**n'ajoute** aucune redaction supplémentaire.

## Discipline navigateur

- Aucun `localStorage`, `sessionStorage`, `document.cookie`.
- Aucun `console.*` sur les payloads API.
- Aucun `navigator.clipboard` dans ce lot (pas de copy-to-clipboard, même
  manuel).
- Aucun envoi de données vers un service externe.
- Aucun stockage React persistant : les états sont uniquement en mémoire du
  composant, purgés à la navigation.

## Contrat UI

- Toutes les actions applicatives passent par `POST/PATCH/DELETE /api/*`
  same-origin (protégés par `assertApiPostAllowed`).
- Aucun `localStorage`, aucun `sessionStorage`.
- Aucun `console.log` de payload API.
- Aucun token brut, aucun claim détaillé, aucune raw response affichés.

## Ce qui n'est pas géré ici

- Aucun token, `client_secret`, `state`, `nonce`, `code_verifier`,
  introspection, ACS SAML, signature XML, session serveur.
- Aucune variable `VITE_*` sensible.
- Aucun `localStorage`/`sessionStorage` pour des données sensibles.

## Build production

```bash
npm --prefix frontend run build
```

Produit `frontend/dist/` avec `base: "/static/"` (voir `vite.config.js`) :
les assets référencés dans `dist/index.html` pointent vers `/static/assets/...`.

En production, le backend Node sert :

- `dist/index.html` sur les routes canoniques SPA (allow-list explicite,
  voir `isSpaRoute` dans `src/server.js`).
- `/static/assets/<hash>.{js,css,...}` → fichier statique de `dist/assets/`.

Le préfixe `/vite/*` est **retiré** (404). Le SSR historique est isolé sous
`/legacy/*` (dev-only ou `ENABLE_LEGACY_SSR=1`).

Le Dockerfile multi-stage build `dist/` dans une étape isolée puis copie
uniquement le résultat dans l'image finale. Aucun `.env`, aucun `data/`,
aucun `node_modules` frontend n'entre dans l'image.
