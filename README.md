# oidc_debug

`oidc_debug` est maintenant un outil simple de test d'integration OpenID Connect centre sur un usage reel:

- une configuration provider globale partagee par toute l'application
- plusieurs configurations de Service Provider reutilisables
- une redirect URI globale derivee de `BASE_URL` pour tous les tests

Cette URI doit aussi etre ajoutee dans la configuration EZ-ACCESS pour que le callback fonctionne.

## Modele fonctionnel

### Configuration provider globale

La configuration provider persiste:

- nom du provider
- discovery URL well-known comme source de verite pour resoudre les endpoints
- redirect URI globale derivee de `BASE_URL` ou forcee via `OIDC_REDIRECT_URI`

Les endpoints sont resolves a l'execution depuis le well-known et ne sont plus saisis dans l'interface.

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
- `OIDC_REDIRECT_URI`: override optionnel de la redirect URI, si differente de `BASE_URL + /oidc/callback`
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

## Endpoints principaux

- `GET /`
- `POST /provider/save`
- `POST /provider/load-discovery`
- `POST /service-providers/save`
- `POST /service-providers/delete`
- `POST /service-providers/select`
- `POST /service-providers/test`
- `GET /oidc/login`
- `GET /oidc/callback`
- `POST /oidc/callback`
- `POST /oidc/token/exchange`
- `POST /oidc/userinfo`
- `GET /oidc/session/:id`

## Notes de securite

- Les secrets clients ne passent plus par des variables d'environnement par configuration.
- Les secrets clients sont chiffres avant ecriture dans `state.json`.
- Les snapshots JSON et l'UI n'exposent jamais les secrets en clair.
- Les logs applicatifs redigent les secrets et tokens.
- Si `SESSION_SECRET` change, les secrets persistants precedemment stockes ne pourront plus etre dechiffres.
- Sans volume persistant sur `STORAGE_DIR`, un redeploiement repartira avec une configuration vide.
