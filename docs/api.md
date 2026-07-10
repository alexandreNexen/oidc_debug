# API JSON (read-only)

Endpoints JSON parallèles au rendu SSR existant. Ce lot n'ajoute **que** des
routes en lecture. Aucune écriture (`POST`/`PATCH`/`DELETE`) n'est exposée.

Les routes SSR historiques (`/oidc/service-providers`, `/oidc/callback`,
`/saml/acs/:spId`, `/oidc/flows/start/:spId`, etc.) ne sont pas modifiées.

## Endpoints

| Méthode | Chemin | Réponse |
| --- | --- | --- |
| GET | `/api/health` | Statut serveur et compteurs |
| GET | `/api/oidc/service-providers` | Liste des SP OIDC (sans `client_secret`) |
| GET | `/api/oidc/flows` | Liste résumée des flows OIDC |
| GET | `/api/oidc/flows/:id` | Détail d'un flow OIDC (steps, tokens, claims, erreurs) |
| GET | `/api/saml/service-providers` | Liste des SP SAML |
| GET | `/api/saml/flows` | Liste résumée des flows SAML |
| GET | `/api/saml/flows/:id` | Détail d'un flow SAML (steps, SAMLResponse, trust, signature) |

Tous les endpoints répondent en `application/json; charset=utf-8` avec les
`SECURITY_HEADERS` habituels (CSP, `X-Frame-Options: DENY`, etc.).

Un flow inconnu renvoie `404` JSON `{ "error": "..." }`. Toute route
`/api/*` non reconnue renvoie `404` JSON.

## Politique de secret

Interdit dans toute réponse API :

- `client_secret` OIDC (jamais renvoyé, y compris chiffré).
- `SESSION_SECRET`, clés dérivées (`sessionSigningKey`, `encryptionKey`).
- `code_verifier` PKCE (retiré via `sanitizeTerminalOidcRuntime`).
- `expectedState`, `expectedNonce` en clair (remplacés par leurs empreintes
  `stateSha256`, `nonceSha256`).
- Contenu brut de `data/state.json`.
- Contenu du cookie de session.

Autorisé dans les endpoints de **détail de flow** (`/api/oidc/flows/:id`,
`/api/saml/flows/:id`) :

- Décodages JWT (`id_token` payload, `access_token` claims quand présents).
- `scopes`, `claims`, `userinfo` exacts.
- `SAMLResponse` décodée, assertion, `nameID`, `sessionIndex`, `issuer`,
  `audience`, `destination`, `subjectConfirmation`.
- Résultat de vérification de signature (`response_signature_verification`,
  `assertion_signature_verification`, `signature_verification_result`).
- Résultat de trust validation (`trust_validation`, `checks`, `errors`,
  `warnings`).
- Codes d'erreur exacts et descriptions (`errorCode`, `errorDescription`).

Rationnel : l'outil est un utilitaire de debug interne. Substituer la valeur
réelle par `"received"`/`"present"` ferait perdre la valeur diagnostique.
Les endpoints **liste** ne renvoient pas de données brutes de token : ils
n'exposent que les métadonnées (id, statut, timing, `serviceProviderName`,
`errorCode`).

## Ce qui n'est pas encore là

- Aucune écriture API. La création/édition de SP se fait toujours par les
  routes SSR existantes.
- Aucun endpoint `/api/oidc/callback` ni `/api/saml/acs`. Les callbacks IdP
  restent gérés par les routes SSR (`/oidc/callback`, `/saml/acs/:spId`).
- Le frontend Vite (`frontend/`) n'est **pas encore branché** sur ces
  endpoints. Il affiche toujours la page d'introduction du lot 1.

## Utilisation dev

```bash
# Backend
npm start

# Curl direct
curl http://localhost:3000/api/health
curl http://localhost:3000/api/oidc/flows
curl http://localhost:3000/api/oidc/flows/<flow-id>

# Via proxy Vite
npm run dev:frontend
curl http://127.0.0.1:5173/api/health
```
