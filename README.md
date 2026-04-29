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
- `SESSION_SECRET`: secret serveur utilise pour le cookie de session et pour chiffrer les secrets stockes
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
- Si `SESSION_SECRET` change, les secrets persistants precedemment stockes ne pourront plus etre dechiffres.
- Sans volume persistant sur `STORAGE_DIR`, un redeploiement repartira avec une configuration vide.
- Sur Render, sans persistent disk monte sur `/app/storage` ou sans `STORAGE_DIR` explicite, la persistance ne survivra pas aux redeploiements.
