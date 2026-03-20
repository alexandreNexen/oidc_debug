# oidc_debug

`oidc_debug` est une application web interne de diagnostic OpenID Connect. Elle permet de charger une configuration OIDC, lancer un Authorization Code Flow, visualiser les requetes/reponses techniques, echanger le `code` contre des tokens, decoder les JWT et appeler `/userinfo`.

## Fonctionnalites V1

- Authorization Code Flow
- Clients `public` et `confidential`
- PKCE optionnel
- Chargement manuel de la configuration OIDC
- Import via Discovery endpoint
- Callback OIDC en `query` ou `form_post`
- Echange `/token`
- Appel `/userinfo`
- Decodage des JWT sans validation cryptographique avancee
- Journal chronologique en memoire par session de debug
- Generation des `curl` equivalents pour `/token`, `/userinfo` et Discovery

## Stack

- Node.js natif sans dependance externe
- Serveur HTTP unique
- UI HTML/CSS/JS legere
- Sessions en memoire

## Variables d'environnement

- `PORT`: port HTTP interne de l'application
- `NODE_ENV`: mode d'execution
- `BASE_URL`: URL publique utilisee pour construire le `redirect_uri` par defaut
- `OIDC_CLIENT_SECRET`: secret client confidentiel, lu uniquement cote serveur pour l'echange `/token`
- `SESSION_SECRET`: secret de signature du cookie de session
- `LOG_LEVEL`: `debug`, `info`, `warn`, `error`
- `STORAGE_DIR`: dossier de persistance des sessions et de la configuration

Un exemple est fourni dans `./.env.example`.

## Lancement avec Docker

```bash
docker compose up --build
```

Application disponible sur `http://localhost:8080`.

Les sessions et la configuration sont persistees dans `./data/state.json` via le volume Docker `./data:/data`.

## Endpoints principaux

- `GET /`
- `GET /config`
- `GET /logs`
- `POST /oidc/config/save`
- `POST /oidc/config/load-discovery`
- `GET /oidc/login`
- `GET /oidc/callback`
- `POST /oidc/callback`
- `POST /oidc/token/exchange`
- `POST /oidc/userinfo`
- `GET /oidc/session/:id`

## Limites connues de cette V1

- Pas de persistance disque
- Pas de multi-utilisateur avance
- Pas de validation de signature JWT
- Pas de support `response_mode=fragment`
- Pas de SAML

## Notes de securite

- Les logs applicatifs redigent les secrets par defaut.
- Le `client_secret` ne doit plus etre saisi dans l'UI. Configure-le uniquement via `OIDC_CLIENT_SECRET` dans l'environnement serveur (Render).
- Les snapshots persistants excluent le `client_secret`.
- Les secrets et tokens sont masques dans l'UI, avec option d'affichage/copie.
- Les sessions de debug sont en memoire et expirees automatiquement.
- Cette application n'est pas destinee a la production.
