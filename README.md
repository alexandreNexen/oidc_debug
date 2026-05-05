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

## Lancement avec Docker

```bash
docker compose up --build
```

Application disponible sur `http://localhost:8080`.

Les donnees sont persistees dans `./data/state.json` et le secret serveur local dans `./data/session-secret` via le volume Docker `./data:/data`.
Sur Render, le chemin par defaut devient `/app/storage`, qui doit correspondre au point de montage d'un persistent disk.

## Endpoints principaux

- `GET /`
- `GET /service-providers`
- `GET /service-providers/new`
- `GET /service-providers/:id/edit`
- `POST /service-providers`
- `POST /service-providers/:id`
- `POST /service-providers/:id/delete`
- `POST /flows/start/:spId`
- `POST /flows/:id/rerun`
- `GET /flows/:id`
- `GET /flows/:id/details`
- `GET /oidc/callback`
- `POST /oidc/callback`
- `GET /health`

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
