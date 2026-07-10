# oidc_debug

`oidc_debug` est un outil simple de test d'integration OpenID Connect centre sur un usage reel:

- un Dashboard
- plusieurs configurations de Service Provider reutilisables
- un choix d'environnement Ez-Access preprod/prod
- un lancement de flow OIDC depuis un Service Provider
- un resultat synthetique et un detail etape par etape du flow

Cette URI doit aussi etre ajoutee dans la configuration EZ-ACCESS pour que le callback fonctionne.

## Modele fonctionnel

### Environnements Ez-Access

Les endpoints OIDC sont resolus a l'execution depuis les discovery URLs configurees par environnement:

- `EZ_ACCESS_PREPROD_DISCOVERY_URL`
- `EZ_ACCESS_PROD_DISCOVERY_URL`

La page `/config` et les anciennes routes de configuration provider libre ne font plus partie du parcours utilisateur.

### Service Providers

Chaque Service Provider contient uniquement:

- nom
- `client_id`
- `client_type`
- `scopes`
- `client_secret` si client confidentiel

Le `client_secret`:

- est saisi via l'UI
- est stocke uniquement cote serveur
- est chiffre avant persistance disque
- n'est jamais renvoye en clair au navigateur

L'UI affiche seulement `Secret configure`, `Aucun secret configure` ou `Non requis`.
Les `scopes` envoyes sont strictement ceux du Service Provider, sans valeur par defaut injectee par l'application.

## Stack

- Node.js natif sans dependance externe
- Serveur HTTP unique
- UI HTML/CSS/JS legere
- Persistance disque dans `data/state.json`

## Variables d'environnement

- `PORT`: port HTTP interne de l'application
- `NODE_ENV`: mode d'execution
- `BASE_URL`: URL publique de l'application
- `RENDER_EXTERNAL_URL`: variable Render detectee automatiquement comme fallback pour l'URL publique par defaut
- `OIDC_REDIRECT_URI`: valeur initiale optionnelle pour pre-remplir la redirect URI globale
- `SESSION_SECRET`: secret maitre utilise pour deriver la cle de signature des cookies de session et la cle de chiffrement AES-256-GCM des secrets stockes (deux cles distinctes derivees via HMAC-SHA256)
- `LOG_LEVEL`: `debug`, `info`, `warn`, `error`
- `STORAGE_DIR`: dossier de persistance

Un exemple est fourni dans `./.env.example`.

Si `SESSION_SECRET` n'est pas fourni, l'application genere un secret local persistant dans `STORAGE_DIR/session-secret`.
Cela permet de conserver le dechiffrement des secrets stockes apres redemarrage ou redeploiement, a condition de conserver le meme `STORAGE_DIR`.

## Frontend Vite (isole, en preparation)

Un dossier `frontend/` accueille une base Vite React strictement isolee. **Aucune
page existante n'a ete migree**, aucune route SSR n'est modifiee, aucun
endpoint `/api` n'est ajoute.

```bash
# Terminal 1 - backend Node (inchange)
npm start

# Terminal 2 - frontend Vite
npm run install:frontend    # premiere fois uniquement
npm run dev:frontend        # lance Vite sur http://127.0.0.1:5173
```

Le proxy Vite renvoie `/oidc/*`, `/saml/*`, `/assets/*`, `/api/*`, `/health`,
`/favicon.svg` et `/favicon.ico` vers le backend Node local (`BACKEND_URL`,
`http://localhost:3000` par defaut). Les callbacks OIDC/SAML restent
exclusivement geres par le backend Node. Details : `frontend/README.md`.

### URL canonique et matrice d'usage dev

| Usage | URL a utiliser |
| --- | --- |
| Tester un vrai flow OIDC/SAML (redirection IdP -> callback) | `http://localhost:3000` (backend direct) |
| Developper l'UI Vite React | `http://127.0.0.1:5173` (Vite dev) |
| Callback OIDC enregistre chez l'IdP | `http://localhost:3000/oidc/callback` |
| ACS SAML enregistre chez l'IdP | `http://localhost:3000/saml/acs/:spId` |

Regle : **l'URL Vite (`127.0.0.1:5173`) ne doit jamais etre enregistree comme
callback OIDC ou ACS SAML aupres d'un IdP.** L'URL canonique du backend
(`BASE_URL`) est la seule source de verite pour construire `redirect_uri` et
`acsUrl`. Cette URL est capturee au demarrage du serveur Node depuis
`process.env.BASE_URL` ; elle n'est jamais recalculee a partir des headers
`X-Forwarded-*` de la requete entrante. Le proxy Vite ne transmet volontairement
pas `X-Forwarded-Host` (`xfwd: false` dans `vite.config.js`) pour eviter tout
risque futur de contamination.

## Lancement avec Docker

```bash
docker compose up --build
```

Application disponible sur `http://localhost:8080`.

Les donnees sont persistees dans `./data/state.json` et le secret serveur local dans `./data/session-secret` via le volume Docker `./data:/data`.
Sur Render, le chemin par defaut devient `/app/storage`, qui doit correspondre au point de montage d'un persistent disk.

## API JSON read-only

Les endpoints suivants exposent en JSON, en parallele des routes SSR, les
memes donnees deja affichees par l'UI actuelle :

- `GET /api/health`
- `GET /api/oidc/service-providers`
- `GET /api/oidc/flows`
- `GET /api/oidc/flows/:id`
- `GET /api/saml/service-providers`
- `GET /api/saml/flows`
- `GET /api/saml/flows/:id`

Aucune ecriture API. Les routes SSR sont inchangees. Details et politique
de secret : `docs/api.md`.

## Frontend Vite en production sur les routes propres

**Vite est le frontend principal** et est servi par le backend Node sur les
routes canoniques sans prefixe. La logique sensible (callbacks IdP,
`/api/*`, `/health`, callbacks OIDC/SAML) reste intacte — aucune n'est
capturee par le SPA grace a une allow-list explicite (`isSpaRoute` dans
`src/routes/spa.js`), et non un catch-all `/oidc/*` / `/saml/*`.

### Modules de routing

Le dispatcher HTTP dans `src/server.js` compose des petits modules a
responsabilite unique :

- `src/routes/api/index.js` — routeur racine `/api/*`. Centralise
  `assertApiPostAllowed` (guard cross-site applique une seule fois), sert
  `GET /api/health`, delegue a `oidc.js` / `saml.js`, renvoie 404 JSON pour
  toute route inconnue.
- `src/routes/api/oidc.js` — endpoints `/api/oidc/*` (SP CRUD, flows,
  discovery import).
- `src/routes/api/saml.js` — endpoints `/api/saml/*` (SP CRUD, flows).
- `src/routes/spa.js` — allow-list SPA + service de `frontend/dist/index.html`.
- `src/routes/static.js` — favicons partages + `/static/assets/*` avec
  protection path traversal.
- `src/routes/health.js` — `GET /health` (probe readiness, hors `/api/*`).
- `src/routes/deprecated.js` — anciennes routes POST canoniques -> 410 Gone.
- `src/legacy-ssr/routes.js` — SSR historique read-only sous `/legacy/*`,
  active uniquement par `ENABLE_LEGACY_SSR=1`.

**Invariant securite** : chaque `POST/PATCH/DELETE /api/*` passe par
`assertApiPostAllowed` exactement une fois, applique au niveau du routeur
racine avant delegation. Aucun sous-routeur ne repete la verification,
aucun ne peut la contourner. Les callbacks (`/oidc/callback`,
`/saml/acs/:spId`) restent explicitement hors de l'arborescence
`/api/*` et gardent leur handler dedie dans `server.js`.

L'ordre du dispatcher est fixe et documente en tete de la fonction
`http.createServer` de `src/server.js`.

Routes exposees en prod :

| Chemin | Servi par |
| --- | --- |
| `/`, `/oidc/service-providers`, `/oidc/service-providers/new`, `/oidc/service-providers/:id/edit`, `/oidc/flows`, `/oidc/flows/:id`, `/saml/service-providers`, `/saml/service-providers/new`, `/saml/service-providers/:id/edit`, `/saml/flows`, `/saml/flows/:id` | Node → `frontend/dist/index.html` (SPA allow-list) |
| `/static/assets/<hash>.{js,css,...}` | Node → `frontend/dist/assets/<hash>...` |
| `/api/*` | API JSON — protege par `assertApiPostAllowed` |
| `/api/oidc/discovery/import/:env` | POST protege par le guard CSRF |
| `/oidc/callback`, `/saml/acs/:spId` | Callbacks IdP — jamais shadowed |
| `/oidc/flows/start/:spId`, `/saml/flows/start/:spId` | Backend redirect vers IdP |
| `/health`, `/favicon.*` | Backend / static |
| `/legacy/*` | SSR historique **dev-only** — voir section ci-dessous |
| `/vite/*` | **Retire** — 404 |
| Route inconnue (typo) | 404 backend — **ne tombe jamais** sur `dist/index.html` |

Toute action applicative (create/edit/delete Service Provider, discovery
import, start/rerun flow) passe par `/api/*`. Les anciennes routes POST
canoniques SSR (`POST /oidc/service-providers`, `POST /oidc/discovery/import/:env`,
etc.) repondent **410 Gone** JSON sans muter d'etat.

En dev, `frontend/` est isole comme avant (`npm run dev:frontend` sur
`127.0.0.1:5173`). En prod, `npm run build:frontend` produit `frontend/dist/`
(base `/static/`) que Node sert directement.

## SSR historique isole sous `/legacy/*`

Les anciennes vues SSR ont ete deplacees sous `src/legacy-ssr/views/` et
leurs assets sous `src/legacy-ssr/assets/`. Elles sont montees en
**lecture seule** sous `/legacy/*` uniquement si :

- `ENABLE_LEGACY_SSR=1` (flag explicite, dev **ET** prod).

`NODE_ENV` seul n'active plus le legacy — dev et prod se comportent
identiquement en l'absence du flag. Sans flag, tout GET `/legacy/*` renvoie
404 JSON. Le SSR historique sert de reference visuelle sur les diagnostics
— il ne modifie plus jamais d'etat (aucun POST). Les URLs internes des
pages SSR (form actions, liens inter-vues, assets) pointent sur
`/legacy/...` afin qu'aucune page legacy ne collide avec les routes
canoniques SPA/API.

Routes legacy exposees quand active :

| Chemin | Rendu |
| --- | --- |
| `/legacy` | Dashboard historique |
| `/legacy/oidc/service-providers`, `/legacy/oidc/service-providers/new`, `/legacy/oidc/service-providers/:id/edit` | Liste / creation / edition OIDC SP |
| `/legacy/oidc/flows/:id`, `/legacy/oidc/flows/:id/details` | Resultat + detail flow OIDC |
| `/legacy/saml/service-providers`, `/legacy/saml/service-providers/new`, `/legacy/saml/service-providers/:id/edit` | Liste / creation / edition SAML SP |
| `/legacy/saml/flows/:id`, `/legacy/saml/flows/:id/details` | Resultat + detail flow SAML |
| `/legacy/assets/app.{css,js}`, `/legacy/assets/brand/*`, `/legacy/assets/icons/*.svg` | Assets legacy (isoles de `/static/assets/*`) |

Build local :

```bash
npm run build:frontend      # produit frontend/dist/ (assets sous /static/)
npm start                   # Node sert la SPA sur les routes canoniques
```

Build Docker (multi-stage, ne copie ni `.env` ni `data/`) :

```bash
docker compose up --build
```

L'image finale contient uniquement :

- backend Node avec `node_modules` production ;
- `src/`, `public/` ;
- `frontend/dist/` (issu du stage de build).

## Endpoints principaux

Pages SPA (Vite servi par le backend, allow-list explicite) :

- `GET /`
- `GET /oidc/service-providers`, `/oidc/service-providers/new`, `/oidc/service-providers/:id/edit`
- `GET /oidc/flows`, `/oidc/flows/:id`
- `GET /saml/service-providers`, `/saml/service-providers/new`, `/saml/service-providers/:id/edit`
- `GET /saml/flows`, `/saml/flows/:id`

Actions applicatives (JSON API, uniquement via `/api/*`) :

- `GET/POST/PATCH/DELETE /api/oidc/service-providers[...]`
- `GET/POST/PATCH/DELETE /api/saml/service-providers[...]`
- `POST /api/oidc/flows/start/:spId`, `POST /api/oidc/flows/:id/rerun`
- `POST /api/saml/flows/start/:spId`, `POST /api/saml/flows/:id/rerun`
- `POST /api/oidc/discovery/import/:env`
- `GET /api/oidc/flows`, `GET /api/oidc/flows/:id`, `GET /api/saml/flows`, `GET /api/saml/flows/:id`
- `GET /api/health`

Callbacks IdP (jamais captures par le SPA) :

- `GET/POST /oidc/callback`
- `POST /saml/acs/:spId`
- `GET/POST /oidc/flows/start/:spId`, `GET/POST /saml/flows/start/:spId`

Divers :

- `GET /health`
- `GET /favicon.svg`, `GET /favicon.ico`
- `GET /static/assets/*` (bundle Vite)
- `GET /legacy/*` — flag `ENABLE_LEGACY_SSR=1` uniquement, sinon 404
- Anciennes routes POST canoniques SSR (`POST /oidc/service-providers`, etc.) → **410 Gone** (voir `src/routes/deprecated.js`)

## Notes de securite

- Les secrets clients ne passent plus par des variables d'environnement par configuration.
- Les secrets clients sont chiffres avant ecriture dans `state.json`.
- Les snapshots JSON et l'UI n'exposent jamais les secrets en clair.
- Les logs applicatifs redigent les secrets et tokens.
- Si `SESSION_SECRET` change, les secrets persistants precedemment stockes ne pourront plus etre dechiffres (la cle de chiffrement est derivee du secret maitre).
- Sans volume persistant sur `STORAGE_DIR`, un redeploiement repartira avec une configuration vide.
- Sur Render, sans persistent disk monte sur `/app/storage` ou sans `STORAGE_DIR` explicite, la persistance ne survivra pas aux redeploiements.
- Le fichier `state.json` est cree avec les permissions `0o600` (lecture/ecriture proprietaire uniquement).

## Security model

### Derivation des cles cryptographiques

A partir du `SESSION_SECRET` (secret maitre), deux cles independantes sont derivees via HMAC-SHA256 avec des contextes domaine distincts :

```
sessionSigningKey = HMAC-SHA256(masterSecret, "oidc-debug:session:v1")
encryptionKey     = HMAC-SHA256(masterSecret, "oidc-debug:encryption:v1")
```

- `sessionSigningKey` : utilise uniquement pour le HMAC des cookies de session
- `encryptionKey` : utilise uniquement pour le chiffrement AES-256-GCM des `client_secret`

Cette separation garantit qu'une compromission d'une surface (analyse de cookies) ne compromet pas l'autre (dechiffrement des secrets).

### Ou les secrets sont manipules

| Donnee | Stockage | Transit | UI navigateur |
|--------|----------|---------|---------------|
| `client_secret` | AES-256-GCM chiffre dans `state.json` (cle derivee separement) | HTTPS uniquement (non impose au niveau applicatif) | Jamais — affiche "Secret configure" uniquement |
| `access_token` | Redige (present/missing) dans `state.json` | HTTPS uniquement | Masque dans les modales raw (6 premiers + 4 derniers chars) |
| `id_token` | Redige dans `state.json` | HTTPS uniquement | Claims selectionnes uniquement (iss, sub, aud, exp, iat, email, name) |
| `refresh_token` | Statut only (present/missing) | HTTPS uniquement | Statut uniquement |
| Authorization code | Statut only dans `state.json` | HTTPS uniquement | Statut uniquement |
| `code_verifier` PKCE | Redige (present/missing) dans `state.json` | HTTPS uniquement | Statut uniquement |
| Cookie de session | HMAC-SHA256 signe (cle derivee separement), non chiffre | HTTPS : flag `Secure` active si `BASE_URL` commence par `https://` | `HttpOnly` — inaccessible au JavaScript |

### Ce qui est volontairement masque

Les fonctions `sanitizeDiagnosticData` et `redactObject` appliquent un masquage systematique sur toutes les donnees passant par les logs, les snapshots et les modales raw :

- `client_secret` → `"********"`
- `access_token`, `id_token`, `refresh_token` → `"received"` ou `"missing"`
- `authorization` (header) → `"Bearer ********"` / `"Basic ********"`
- `code`, `code_verifier` → `"present"` ou `"missing"`
- `cookie`, `set-cookie` → `"********"`
- `secretRecord` → `"configured"` ou `"missing"`

### Ce qui est affichable cote UI

- Nom, `client_id`, scopes, environnement du Service Provider
- Statuts des etapes du flow (success/error/skipped)
- Claims selectionnes de l'ID token : `iss, sub, aud, exp, iat, email, name, groups, roles`
- Claims de l'endpoint UserInfo (memes champs selectionnes)
- URL d'autorisation complete (contient `state`, `nonce`, `code_challenge` — non secrets)
- Erreurs OIDC brutes (`error`, `error_description`)

### Limites de l'outil

- **Pas d'authentification** : l'acces a l'application n'est protege que par le reseau. A deployer uniquement sur un reseau prive ou derriere un proxy authentifie.
- **Pas de validation de signature JWT** : cet outil affiche les claims sans verifier la signature des tokens. Il est concu pour le diagnostic, pas pour valider une integration en production.
- **Rate limiting en memoire** : la protection contre les envois repetitifs (20 creations SP / 10 starts flow par session par 5 minutes) est perdue au redemarrage du serveur.
- **`SESSION_SECRET` critique** : si ce secret est compromis, les sessions peuvent etre forgees et les `client_secret` stockes peuvent etre dechiffres. Proteger ce secret comme une credential de production.
- **Migration cassante** : un changement de `SESSION_SECRET` invalide tous les `client_secret` chiffres stockes. Les Service Providers doivent etre re-saisis.

### Garanties pour une integration SI prive

- Le `client_secret` n'est jamais transmis au navigateur ni present dans aucune reponse HTTP ou HTML.
- Les tokens ne sont jamais loggues en clair.
- Les erreurs serveur (HTTP 500) ne revelent pas de message interne ni de stack trace.
- Les corps de requete sont limites a 64 Ko — une reponse 413 est retournee si depassement.
- Un rate limiting par session protege les routes mutantes (creation SP, demarrage de flow).
- Les headers de securite sont envoyes sur toutes les reponses : `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`, et `Strict-Transport-Security` si HTTPS.
- Le cookie de session est `HttpOnly; SameSite=Lax` + `Secure` si `BASE_URL` est en HTTPS.
- La cle de chiffrement AES-256-GCM et la cle de signature HMAC sont derivees separement du `SESSION_SECRET` via HMAC-SHA256 avec contextes domaine distincts, avec IV aleatoire par enregistrement et tag d'authentification GCM.
- Le fichier `state.json` est ecrit avec les permissions `0o600` via ecriture atomique (fichier temporaire + rename).

### Commandes de validation

```bash
# Lancer les tests de securite
npm test

# Verifier qu'aucun client_secret n'apparait en clair dans state.json
grep -i "client_secret" data/state.json && echo "FAIL: client_secret en clair" || echo "OK: pas de client_secret en clair"

# Verifier que state.json contient bien des enregistrements chiffres (pas de valeur brute)
grep -c '"algorithm": "aes-256-gcm"' data/state.json

# Rechercher des secrets potentiels commites dans le repo
git log --all --full-history -- "*.json" "*.env" | head -20
grep -rn "change-me\|password\|secret" --include="*.js" --include="*.json" --include="*.yml" . \
  --exclude-dir=node_modules --exclude-dir=data

# Build de verification (syntaxe Node.js)
node --check src/server.js && node --check src/oidc.js && echo "OK: pas d'erreur de syntaxe"
```
