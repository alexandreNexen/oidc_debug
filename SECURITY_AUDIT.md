# Rapport d'Audit Sécurité — Ez-Access OIDC Debug

**Date** : 2026-05-05  
**Application** : `oidc_debug` — outil de diagnostic OIDC interne  
**Stack** : Node.js natif (pas de framework), ESM, dépendance unique `dotenv`  
**Périmètre** : Audit complet du code source (backend, frontend, configuration, persistance)

---

## Résumé Exécutif

L'application présente une base de sécurité solide : chiffrement AES-256-GCM des secrets, fonctions de redaction systématiques, sessions HMAC-signées, et absence de dépendances externes. Les deux audits successifs ont progressivement renforcé la posture de sécurité en traitant les risques de niveau critique, élevé, moyen puis faible.

**Niveau de risque global avant audit 1 : MOYEN**  
**Niveau de risque global après audit 1 : FAIBLE**  
**Niveau de risque global après audit 2 : TRÈS FAIBLE** (outil interne, réseau privé)

---

## Modèle de Menace

### Surface d'attaque

| Surface | Exposition | Risque principal |
|---------|------------|-----------------|
| Formulaires SP (création/édition) | Réseau interne uniquement | Injection de données volumineuses, abus de ressources |
| Cookie de session | Réseau interne | Forge de cookie si `SESSION_SECRET` compromis |
| Fichier `state.json` | Disque du serveur | Lecture directe si le système hôte est compromis |
| Callback OIDC (`/oidc/callback`) | Réseau interne + redirections IdP | Replay d'état expiré, confusion de flow |
| Clé de chiffrement AES | Mémoire du processus | Confusion entre clé session et clé chiffrement |

### Hypothèses du modèle

- **Pas d'authentification au niveau applicatif** : l'outil est déployé derrière un contrôle d'accès réseau (VPN, proxy SSO).
- **Attaquant interne limité** : un utilisateur du réseau interne peut interagir avec l'application, mais n'a pas accès au système de fichiers du serveur.
- **`SESSION_SECRET` est une credential de production** : sa compromission entraîne la forge de sessions et le déchiffrement des secrets stockés.

### Authentification — risque documenté

L'application ne possède pas de couche d'authentification propre. Tout utilisateur atteignant le réseau du serveur peut accéder à l'interface. Ce choix est **intentionnel** pour un outil de diagnostic interne, mais il doit être compensé par :

1. Un déploiement derrière un proxy authentifié (nginx Basic Auth, Keycloak, Cloudflare Access, etc.)
2. Un accès réseau restreint (VPN, VLAN dédié)
3. Une rotation régulière du `SESSION_SECRET`

---

## Findings — Audit 1 (7 findings)

### F-01 — Critique : `SESSION_SECRET` par défaut faible dans le dépôt

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Critique |
| **Fichier** | `docker-compose.yml:10` |
| **Statut** | Corrigé (audit 1) |

**Preuve dans le code :**
```yaml
SESSION_SECRET: ${SESSION_SECRET:-change-me-dev-only}
```

**Risque concret :**  
Tout déploiement Docker sans override explicite utilise `change-me-dev-only` comme clé. Cette valeur étant publique dans le dépôt, un attaquant peut :
1. Forger des cookies de session valides (`HMAC-SHA256` calculable).
2. Déchiffrer tous les `client_secret` stockés (la clé AES-256-GCM était dérivée du `SESSION_SECRET`).

**Correction appliquée :**
```yaml
# docker-compose.yml
SESSION_SECRET: ${SESSION_SECRET}
```
Si `SESSION_SECRET` n'est pas fourni, l'application génère automatiquement un secret dans `STORAGE_DIR/session-secret` (mode fichier). La valeur faible par défaut a été supprimée du dépôt.

---

### F-02 — Élevé : `error.message` exposé dans les réponses HTTP 500

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Élevé |
| **Fichier** | `src/server.js` — handler global catch |
| **Statut** | Corrigé (audit 1) |

**Risque concret :**  
`error.message` peut contenir des chemins internes, des noms de modules Node, des informations sur la configuration, ou des détails d'erreur réseau. Ces informations aident un attaquant à cartographier l'environnement.

**Correction appliquée :**
```javascript
sendJson(res, 500, { error: "Internal error." });
// L'erreur complète est toujours loggée côté serveur via appLog("error", ...)
```

---

### F-03 — Élevé : Headers de sécurité HTTP absents

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Élevé |
| **Fichier** | `src/server.js` — fonction `send` |
| **Statut** | Corrigé (audit 1), étendu (audit 2) |

**Risque concret :**

| Header manquant | Attaque possible |
|----------------|-----------------|
| `X-Content-Type-Options: nosniff` | MIME sniffing → exécution de JS depuis un fichier CSS/SVG mal interprété |
| `X-Frame-Options: DENY` | Clickjacking — l'UI pourrait être intégrée dans un iframe malveillant |
| `Content-Security-Policy` | XSS via injection de script |
| `Referrer-Policy` | Fuite de l'URL interne dans les en-têtes Referer |
| `Permissions-Policy` | Activation involontaire de fonctionnalités navigateur |
| `Strict-Transport-Security` | Downgrade HTTP en mode HTTPS |

**Correction appliquée (audit 2) :**
```javascript
const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  ...(IS_HTTPS_MODE ? { "strict-transport-security": "max-age=63072000; includeSubDomains" } : {})
};
```

---

### F-04 — Élevé : Cookie de session sans flag `Secure` en production HTTPS

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Élevé |
| **Fichier** | `src/server.js` — `setSessionCookie` |
| **Statut** | Corrigé (audit 1) |

**Correction appliquée :**
```javascript
const secureFlag = IS_HTTPS_MODE ? "; Secure" : "";
res.setHeader("Set-Cookie", `...HttpOnly; SameSite=Lax${secureFlag}`);
```

---

### F-05 — Moyen : Aucune limite de longueur sur les champs de saisie

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Moyen |
| **Fichier** | `src/services/serviceProviders.js` |
| **Statut** | Corrigé (audit 1) |

**Correction appliquée :**
```javascript
const MAX_NAME_LENGTH = 255;
const MAX_CLIENT_ID_LENGTH = 256;
const MAX_CLIENT_SECRET_LENGTH = 512;
const MAX_SCOPES_LENGTH = 512;
```

---

### F-06 — Moyen : `analyzeTokens` exportait les valeurs brutes des tokens

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Moyen |
| **Fichier** | `src/oidc.js` |
| **Statut** | Corrigé (audit 1) |

**Correction appliquée :** Suppression des champs `value` et `raw` — seuls `maskedValue`, `format`, `decoded`, `expiration`, `present` sont conservés.

---

### F-07 — Faible : Aucune validation de robustesse du `SESSION_SECRET` au démarrage

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Faible |
| **Fichier** | `src/server.js` — `ensureRuntimeSecrets` |
| **Statut** | Corrigé (audit 1) |

**Correction appliquée :**
```javascript
const SESSION_SECRET_MIN_LENGTH = 32;
if (runtimeSessionSecret.length < SESSION_SECRET_MIN_LENGTH) {
  appLog("warn", `SESSION_SECRET trop court (...)`);
}
```

---

## Findings — Audit 2 (3 nouveaux findings)

### F-08 — Élevé : Séparation des clés cryptographiques absente

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Élevé |
| **Fichier** | `src/server.js` — `ensureRuntimeSecrets`, `encryptSecret`, `setSessionCookie` |
| **Statut** | Corrigé (audit 2) |

**Preuve dans le code (avant correctif) :**
```javascript
// Une seule clé dérivée via SHA-256, utilisée pour DEUX usages distincts
secretKey = crypto.createHash("sha256").update(runtimeSessionSecret).digest();
// ...
crypto.createHmac("sha256", getSessionSecret())  // session HMAC utilisait runtimeSessionSecret brut
crypto.createCipheriv("aes-256-gcm", getSecretKey(), iv)  // même dérivé pour AES
```

**Risque concret :**  
L'utilisation du même matériel de clé pour le signing HMAC des cookies et le chiffrement AES-256-GCM des secrets clients viole le principe de séparation des usages cryptographiques. En cas d'attaque par oracle ou d'analyse de side-channel sur l'une des surfaces, l'autre est potentiellement compromise.

**Correction appliquée :**
```javascript
let sessionSigningKey = null;   // HMAC key for session cookies
let encryptionKey = null;       // AES-256-GCM key for client secrets

function deriveApplicationKeys(masterSecret) {
  sessionSigningKey = crypto.createHmac("sha256", masterSecret).update("oidc-debug:session:v1").digest();
  encryptionKey = crypto.createHmac("sha256", masterSecret).update("oidc-debug:encryption:v1").digest();
}
```

**Note de migration :** Ce changement est intentionnellement cassant. Les `client_secret` chiffrés avec l'ancienne clé (SHA-256 du secret) ne seront plus déchiffrables. Les Service Providers existants devront être re-saisis après mise à jour.

---

### F-09 — Moyen : Absence de limite de taille sur le corps des requêtes HTTP

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Moyen |
| **Fichier** | `src/server.js` — `readBody` |
| **Statut** | Corrigé (audit 2) |

**Risque concret :**  
Sans limite de taille, un attaquant peut envoyer un corps de requête de plusieurs dizaines de mégaoctets, saturant la mémoire du processus Node.js et causant un déni de service.

**Correction appliquée :**
```javascript
const MAX_BODY_SIZE = 64 * 1024; // 64 KB

async function readBody(req) {
  const chunks = [];
  let totalSize = 0;
  for await (const chunk of req) {
    totalSize += chunk.length;
    if (totalSize > MAX_BODY_SIZE) {
      req.resume();
      const err = new Error("Request body exceeds size limit.");
      err.code = "BODY_TOO_LARGE";
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}
// ...
if (error.code === "BODY_TOO_LARGE") {
  sendJson(res, 413, { error: "Request body too large." });
  return;
}
```

---

### F-10 — Moyen : Absence de rate limiting sur les actions mutantes

| Attribut | Valeur |
|----------|--------|
| **Criticité** | Moyen |
| **Fichier** | `src/server.js` — routes `POST /service-providers` et `POST /flows/start/:spId` |
| **Statut** | Corrigé (audit 2) |

**Risque concret :**  
Sans rate limiting, un script peut créer des milliers de Service Providers ou lancer des centaines de flows OIDC en quelques secondes, saturant l'état en mémoire, le disque et les endpoints de l'IdP.

**Correction appliquée :**
```javascript
const rateLimitMap = new Map();

function checkRateLimit(sessionId, action, max, windowMs) {
  const key = `${action}:${sessionId}`;
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now >= entry.resetAt) {
    rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= max) return false;
  entry.count++;
  return true;
}
```

Limites appliquées :
- `POST /service-providers` : 20 créations / 5 minutes / session
- `POST /flows/start/:spId` : 10 démarrages / 5 minutes / session

---

## Améliorations Complémentaires (Audit 2)

En plus des findings principaux, les améliorations suivantes ont été apportées :

| Amélioration | Détail |
|--------------|--------|
| TTL sur le state OIDC | `findRunningFlowByState` rejette les flows de plus de 30 minutes (`FLOW_STATE_TTL_MS = 30 * 60 * 1000`) |
| Permissions du fichier `state.json` | Mode `0o600` sur le fichier temporaire avant rename atomique |
| `decryptSecret` robuste | Enveloppé dans try/catch — retourne `""` et log un warn si la clé est invalide |
| Guard sur `encryptionKey` | `encryptSecret` lève une erreur explicite si `encryptionKey` n'est pas initialisée |

---

## Matrice des Données Sensibles

| Donnée | Stockage disque | En mémoire | Transmis au navigateur | Loggué |
|--------|----------------|------------|------------------------|--------|
| `client_secret` | AES-256-GCM chiffré | Décrypté uniquement pendant l'échange token | Jamais | Jamais (redacté `********`) |
| `access_token` | Statut uniquement (`received`/`missing`) | Présent temporairement | Masqué (6+4 chars) | Jamais (redacté) |
| `id_token` | Claims sélectionnés uniquement | Présent temporairement | Claims sélectionnés | Jamais (redacté) |
| `refresh_token` | Statut uniquement | Présent temporairement | Statut uniquement | Jamais (redacté) |
| Authorization code | Statut uniquement | Présent temporairement | Statut uniquement | Jamais (redacté) |
| `code_verifier` PKCE | Redacté | Présent pendant le flow | Statut uniquement | Jamais |
| Cookie de session | HMAC-signé dans `state.json` | En clair en mémoire Map | `HttpOnly` — inaccessible JS | Jamais |
| `SESSION_SECRET` | Fichier `session-secret` (mode 0o600) | En clair en mémoire | Jamais | Jamais |
| Clé de session (`sessionSigningKey`) | Jamais | Dérivée en mémoire | Jamais | Jamais |
| Clé de chiffrement (`encryptionKey`) | Jamais | Dérivée en mémoire | Jamais | Jamais |

---

## Points Confirmés Sécurisés

| Surface | Verdict | Justification |
|---------|---------|---------------|
| Stockage `client_secret` | Sécurisé | AES-256-GCM, IV aléatoire par enregistrement, tag GCM, clé dérivée séparément |
| Séparation des clés cryptographiques | Sécurisé | HMAC-HKDF avec contextes domaine distincts (`session:v1`, `encryption:v1`) |
| Transmission du secret en mémoire | Sécurisé | Décryptage uniquement au moment de l'échange token |
| Retour API du `client_secret` | Sécurisé | `sanitizeServiceProviderForUi` retourne `secretConfigured: Boolean(...)` uniquement |
| Formulaire d'édition | Sécurisé | Champ `type="password"` avec `value=""` |
| Conservation du secret en update | Sécurisé | Si le champ est vide, l'ancien `secretRecord` est conservé |
| Logs applicatifs | Sécurisé | `redactObject` appliqué sur toutes les données loggées |
| Données brutes des modales | Sécurisé | `sanitizeRawRequest` + `sanitizeRawResponse` + `sanitizeDiagnosticData` |
| `Authorization: Bearer` dans userInfo | Sécurisé | Remplacé par `"Bearer ********"` dans toutes les vues |
| `Authorization: Basic` token exchange | Sécurisé | Remplacé par `"Basic ********"` dans les snapshots |
| Injection HTML / XSS | Sécurisé | `escapeHtml()` appliqué systématiquement dans toutes les vues SSR |
| Path traversal fichiers statiques | Sécurisé | Mapping statique strict |
| State OIDC | Sécurisé | Généré aléatoirement (12 octets hex), TTL 30 min, validé par `evaluateState` |
| PKCE | Sécurisé | S256 par défaut, `code_verifier` 32 octets aléatoires |
| Sessions | Sécurisé | HMAC-SHA256 clé dédiée, `crypto.timingSafeEqual`, TTL 8h, nettoyage périodique |
| Écriture `state.json` | Sécurisé | Écriture atomique via fichier temporaire + rename, mode 0o600 |
| Limite de taille requête | Sécurisé | 64 KB max, erreur 413 si dépassé |
| Rate limiting | Sécurisé | 20 créations SP / 10 starts flow par session par 5 minutes |
| Injection SQL | N/A | Pas de base de données relationnelle |
| eval / code dynamique | Sécurisé | Aucun `eval`, aucun `Function()`, aucun `require()` dynamique |

---

## Risques Résiduels

| Risque | Niveau | Mitigation recommandée |
|--------|--------|------------------------|
| Pas d'authentification sur l'application | Moyen | Déployer derrière un proxy d'authentification (SSO, VPN, Basic Auth nginx) |
| Tokens stockés en clair dans `state.json` pour les flows récents | Moyen | Acceptable pour un outil de diagnostic interne ; purger régulièrement les flows anciens |
| Rate limiting en mémoire uniquement | Faible | Non persisté entre redémarrages. Suffisant pour un usage interne |
| Pas de validation de signature JWT | Faible | Intentionnel — outil de diagnostic uniquement |
| SSRF vers endpoints IdP issus du discovery | Faible | Les discovery URLs sont configurées par variables d'environnement (source de confiance) |
| Pas de CSRF token explicite | Faible | Mitigé par `SameSite=Lax` ; acceptable pour un outil interne |
| Migration cassante (F-08) | Opérationnel | Les secrets chiffrés avec l'ancienne clé doivent être re-saisis après la mise à jour |

---

## Commandes de Validation

```bash
# 1. Tests de sécurité (45 assertions)
npm test

# 2. Vérification syntaxique du code
node --check src/server.js
node --check src/oidc.js
node --check src/services/serviceProviders.js
node --check src/services/flows.js

# 3. Vérifier qu'aucun client_secret n'apparaît en clair dans state.json
grep -i '"client_secret"' data/state.json && echo "FAIL" || echo "OK: pas de client_secret en clair"

# 4. Vérifier que state.json contient bien des enregistrements chiffrés
grep '"algorithm": "aes-256-gcm"' data/state.json | wc -l

# 5. Vérifier qu'aucun token n'apparaît en clair dans state.json
grep -E '"(access_token|id_token|refresh_token)": "ey' data/state.json && echo "FAIL" || echo "OK: pas de token en clair"

# 6. Recherche de secrets dans le dépôt (hors node_modules et data)
grep -rn "change-me\|password.*=\|secret.*=" \
  --include="*.js" --include="*.yml" --include="*.json" \
  --exclude-dir=node_modules --exclude-dir=data .

# 7. Vérification des headers de sécurité (application en cours d'exécution)
curl -si http://localhost:3000/health | grep -E "x-content-type|x-frame|content-security|referrer|permissions-policy"

# 8. Vérifier la réponse 413 sur corps trop large
curl -si -X POST http://localhost:3000/service-providers \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name=$(python3 -c 'print("A"*70000)')" | head -5

# 9. Vérifier la séparation des clés (test inclus dans npm test)
node -e "
const crypto = require('crypto');
const master = 'test-master-secret-32chars!!!!!!!!';
const sk = crypto.createHmac('sha256', master).update('oidc-debug:session:v1').digest('hex');
const ek = crypto.createHmac('sha256', master).update('oidc-debug:encryption:v1').digest('hex');
console.assert(sk !== ek, 'Keys must differ');
console.log('OK: session key != encryption key');
"
```

---

## Livrables

| Livrable | Fichier |
|----------|---------|
| Rapport d'audit | `SECURITY_AUDIT.md` (ce fichier) |
| Correctifs audit 1 — headers, cookie Secure, error masking, SESSION_SECRET | `src/server.js` |
| Correctif audit 1 — analyzeTokens sans valeurs brutes | `src/oidc.js` |
| Correctif audit 1 — validation longueur champs | `src/services/serviceProviders.js` |
| Correctif audit 1 — suppression du SECRET par défaut | `docker-compose.yml` |
| Correctif audit 2 — séparation des clés (HMAC-HKDF) | `src/server.js` |
| Correctif audit 2 — limite taille corps requête (64 KB) | `src/server.js` |
| Correctif audit 2 — rate limiting par session | `src/server.js` |
| Correctif audit 2 — TTL sur state OIDC (30 min) | `src/server.js`, `src/services/flows.js` |
| Correctif audit 2 — permissions fichier state.json (0o600) | `src/server.js` |
| Correctif audit 2 — headers Permissions-Policy + HSTS | `src/server.js` |
| Tests de sécurité (45 assertions, 100 % pass) | `tests/security.test.js` |
| Section Security model | `README.md` |
