# SPEC: PaaS Edge Gateway & Ingress Proxy (Rust)

## 1. Vision & Objectifs du Projet
* **Nature du projet :** Reverse proxy Edge haute performance, spécialisé pour un PaaS multi-tenant isolant (1 VM frontale/gateway routant vers un réseau privé de VMs applicatives par client).
* **Philosophie :** 
  * **KISS / YAGNI :** Pas de Kubernetes, pas de dépendance externe lourde (zéro Redis, zéro etcd, zéro base de données externe). Tout tient dans un binaire statique unique.
  * **Convention over Configuration :** Configuration déclarative textuelle simple (KDL).
  * **Empreinte minimale :** Consommation cible **< 32 Mo de RAM**, zéro pause de Garbage Collection (pile Rust pure).

---

## 2. Stack Technique (Crates Rust imposées)
* **Moteur Réseau & HTTP :** `tokio` (runtime asynchrone), `hyper` (v1.0), `hyper-util`.
* **Sécurité & TLS :** `rustls`, `tokio-rustls`, `instant-acme` (gestion Let’s Encrypt native).
* **Stockage persistant local :** `rusqlite` (mode WAL) pour stocker les certificats TLS et les états locaux.
* **Routage :** `matchit` (Radix Tree ultra-rapide) wrappé dans un `ArcSwap` (swaps atomiques de configuration à chaud).
* **Parsing de config :** `kdl` (syntaxe de configuration).
* **Rate-Limiting & Résilience :** `governor` (Token Bucket lock-free), `async-compression` (Zstd/Brotli).
* **Observabilité & MCP :** `tracing`, anneau circulaire personnalisé (`RingBuffer`) pour le Flight Recorder, et un serveur MCP natif (`sse` ou `json-rpc`) pour l'assistance IA/Support.

---

## 3. Architecture Fonctionnelle & Modules Core

### A. Core Proxy & Contrôle d'accès (Data Plane)
1. **Terminaison TLS & ACME :** Renouvellement automatique des certificats par domaine via `instant-acme`, persistés dans SQLite (`certs.db`). Pas de fichier `acme.json` monolithique. Le TLS est optionnel par route (sans nœud `tls`, la route est servie en HTTP uniquement) et fonctionne selon deux modes, décrits en section 4.1 :
   * **auto** (`tls`) : certificat local valide du répertoire `certs-dir`, sinon certificat Let's Encrypt, sinon certificat auto-signé temporaire, de façon transparente et par hôte ;
   * **auto-signé** (`tls self-signed=#true`) : certificat généré en mémoire, éphémère.
2. **Routage par IP Privée (Upstream Pool) :** Routage Host-based vers des IPs privées (`10.0.x.y:port`).
3. **Active Health-Checking :** Tâche de fond `tokio` par upstream effectuant des ponds continus. Si un backend est injoignable, retrait instantané de la table de routage en mémoire.
4. **Page de Fallback Inline (Maintenance) :** En cas de 502/503 ou de timeout réseau, service immédiat d'une page HTML/JSON de secours embarquée en mémoire avec affichage d'un **Incident ID** (qui est le `trace_id` W3C).
5. **Convention over Configuration :** Tous les parametres doivent avoir des configurations "par défaut de bon sens"

### B. Le Gatekeeper (Authentification Non-Tech / Pre-prod)
Destiné à protéger les environnements de staging/dev (`dev.client.com`) sans configuration tierce (zéro OAuth externe) :
1. **Mode PSK (Mot de passe de site) :** Formulaire de login ultra-léger (HTML inliné, assets zéro-CDN). Hash Argon2id vérifié localement. Pose d'un cookie `HttpOnly` sécurisé.
2. **Rate-Limiting d'authentification :** Protection anti-brute-force intégrée en mémoire via `governor`.
3. **TOTP built-in :**

### C. Les "Quick Wins" intégrés (Fonctionnalités type Enterprise)
1. **Cache HTTP RFC 9111 :** Cache en mémoire/mmap avec support de `stale-while-revalidate` et purge par tags (`Surrogate-Key`).
2. **Validation JWT Native :** Décodage et vérification cryptographique (RSA/HMAC/EdDSA) en <50µs via `jsonwebtoken`, avec injection des `claims` dans les headers de la requête vers le backend (`X-User-Id`, etc.).
3. **API Key Authentication :** Vérification par hachage SHA-256 de clés d'API passées en header.
4. **Rate-Limiting par IP/Route :** Implémenté via `governor` (zéro allocation).
5. **GeoIP Filtering / Enrichment :** Lecture d'une base MaxMind `.mmdb` en `mmap` pour bloquer des pays ou injecter `X-Country-Code`.
6. **Compression Gzip / Zstd / Brotli :** Streaming asynchrone des réponses.
7. **Payload transformation: ** Req/Resp Headers injection/deletion/regex-subs, status code
8. **IP Allowlist par route :** liste optionnelle de réseaux autorisés (`allow-ips`, CIDR ou IP, IPv4 et IPv6). Absente : aucun filtrage. Hors liste : 403. Des listes nommées (`ip-set`), déclarées une fois, sont réutilisables dans toutes les routes et dans `trusted-proxies`. Une entrée par ligne pour pouvoir commenter chaque plage.

### D. Observabilité & Flight Recorder
1. **W3C Trace Context :** Génération/propagation d'un en-tête `traceparent`. L'ID d'incident affiché au client en cas de panne **est** le `trace_id`.
2. **Ring Buffer d'Erreurs :** Conservation en mémoire vive des 500 dernières requêtes en erreur (4xx/5xx/timeout) avec horodatage et contexte réseau.
3. **Serveur MCP Intégré (Model Context Protocol) :**
   * Exposition d'un serveur local (ou sécurisé par token) permettant à un agent IA (Cursor, Claude Desktop) d'interroger l'état de la gateway.
   * **Outils MCP exposés :** `get_route_status`, `query_flight_recorder`, `inspect_incident(id)`, `purge_cache`.

---

## 4. Schéma de Configuration de Référence (Format KDL)

Le fichier de configuration unique (généré ou synchronisé par GitOps sur la VM frontale) doit respecter cette structure :

```kdl
gateway {
    listen ":80" ":443"
    storage-path "/var/lib/gateway/certs.db"
}

mcp-server {
    listen "127.0.0.1:9090"
    token "secret-mcp-token-interne"
}

route "client.com" "www.client.com" {
    tls email="admin@monpaas.net"

    // Upstreams avec répartition de charge (Blue/Green / Canary)
    upstream "10.0.1.10:8080" weight=90
    upstream "10.0.1.20:8080" weight=10

    // Fonctionnalités Avancées intégrées
    cache max-size="256MB" stale-while-revalidate=30
    compression zstd=true brotli=true
    geoip database="/var/lib/geoip/GeoLite2-Country.mmdb" block-countries="CN,RU"

    fallback status=503 show-incident-id=true
}

// Liste nommée, réutilisable par plusieurs routes
ip-set "staff" {
    - "203.0.113.0/24"   // bureau
    - "198.51.100.7"     // sortie VPN
}

route "dev.client.com" {
    tls email="admin@monpaas.net"
    upstream "10.0.1.11:8080"

    gatekeeper {
        title "Environnement de Prévisualisation"
        psk "$argon2id$v=19$m=19456,t=2,p=1$..." // Hash argon2id de la PSK
        session-duration "14d"
        rate-limit attempts=5 window="15m"
    }

    jwt-validation {
        secret-env "JWT_SECRET_KEY"
        issuer "https://auth.client.com"
        inject-headers true
    }

    // Seuls ces clients atteignent la route (403 sinon)
    allow-ips {
        - "staff"
        - "192.0.2.10"       // prestataire
    }
}
```

### 4.1 Modes TLS

```kdl
gateway {
    certs-dir "/etc/paasers/certs"            // optionnel : répertoire de certificats locaux
    acme-directory "production"               // défaut global (production | staging | URL https)
}

route "client.com" "www.client.com" { tls }                       // auto : local si présent, sinon Let's Encrypt
route "dev.client.com" { tls { staging } }                        // auto, Let's Encrypt staging pour cette route
route "*.preview.client.com" { tls }                              // wildcard : exige un certificat local
route "intranet.lan" { tls self-signed=#true }                    // auto-signé en mémoire
route "plain.client.com" { }                                      // HTTP uniquement
```

* **Mode auto, ordre de choix par hôte :** (1) certificat local valide, (2) certificat ACME valide, (3) certificat local expiré en dernier recours, avec incident, (4) certificat auto-signé temporaire. Ce choix est réévalué au démarrage, au rechargement, à chaque changement du répertoire et à chaque expiration.
* **`certs-dir` :** tout le répertoire est analysé, sans contrainte de nom de fichier. Les clés et les certificats sont appariés par clé publique et associés aux hôtes par leurs SAN. À validité égale, celui qui expire le plus tard l'emporte. Les renouvellements externes (certbot, etc.) sont pris en compte sans redémarrage.
* **Continuité de service :** l'émission ACME démarre 30 jours avant l'expiration du certificat local (ou immédiatement s'il n'y en a pas), pendant que le certificat local continue d'être servi.
* **`staging` :** nœud enfant optionnel de `tls`, il impose Let's Encrypt staging pour la route et prime sur `acme-directory`.
* **Mode auto-signé :** incompatible avec `email` et `staging`. Les wildcards sont acceptés. Le certificat n'est jamais stocké ni remplacé par ACME, et change à chaque redémarrage.
* **Contraintes :** ACME (HTTP-01) est impossible pour un wildcard ou sans email (`email=` ou `default-email`). Un hôte sans certificat local ni ACME possible est une erreur de configuration. Un hôte avec certificat local mais sans ACME possible produit un avertissement (pas de repli).
* **`redirect-https` :** vaut `#true` par défaut pour tous les modes TLS.
* **Observabilité :** chaque changement de source de certificat est journalisé et enregistré comme incident `tls_fallback`. Le MCP expose la source de chaque hôte (`local`, `acme`, `local-expired`, `self-signed`).
* `cert-file` et `key-file` n'existent pas : un répertoire de certificats les remplace.

### 4.2 IP Allowlist et listes nommées

```kdl
// Liste nommée, déclarée une fois au premier niveau, réutilisable partout
ip-set "staff" {
    - "203.0.113.0/24"     // bureau
    - "2001:db8:42::/48"   // bureau, IPv6
    - "198.51.100.7"       // sortie VPN
}

route "admin.client.com" {
    upstream "10.0.1.20:8080"
    allow-ips {
        - "staff"              // référence à la liste nommée
        - "192.0.2.10"         // prestataire
        /- - "192.0.2.0/24"    // entrée désactivée
    }
}

gateway {
    trusted-proxies {          // même syntaxe de liste
        - "10.0.0.2"           // load balancer frontal
    }
}
```

* **Absence de `allow-ips` :** aucun filtrage (pas de `0.0.0.0/0` implicite, qui oublierait l'IPv6).
* **Entrée :** CIDR ou IP seule (IPv4 ou IPv6), sinon nom d'un `ip-set`. Une entrée par enfant `-`, la forme positionnelle `allow-ips "a" "b"` reste acceptée pour les listes courtes.
* **`ip-set` :** contient uniquement des réseaux (pas d'imbrication), nom unique, jamais vide.
* **Refus :** 403 via la page d'erreur de la gateway (Incident ID), incident `ip_blocked`. Le filtre est la première couche de la route : un client refusé ne consomme ni rate-limit, ni gatekeeper, ni backend.
* **IP client :** celle déjà utilisée par le rate-limit et la GeoIP (`X-Forwarded-For` n'est lu que si le pair TCP est dans `trusted-proxies`).
* **Pas de `deny`** (YAGNI). Détails : `plans/15-ip-allowlist.md`.

---

## 5. Directives d'implémentation pour l'Agent IA (Prompts d'exécution)

Respecter strictement ces règles de code :
1. **Zéro unwrapping sauvage :** Gestion propre des erreurs avec `anyhow`, `thiserror`, `fastrace`. Le proxy ne doit *jamais* paniquer (`panic!`) sur un trafic mal formé ou une défaillance réseau d'un backend.
2. **Concurrence sans verrou lourd :** Utiliser `tokio::sync` et `arc-swap` pour la configuration dynamique.
3. **Tests unitaires obligatoires :** Chaque module (parsing KDL, validation JWT, calcul de rate-limit, formatage du Flight Recorder) doit comporter des tests unitaires intégrés.
4. **Modularité :** Isoler chaque Quick Win (JWT, Cache, GeoIP) dans un module Tower distinct (`tower::Layer` / `tower::Service`) pour garder un code propre et testable unitairement.
5. **Up-to-date :** Utilise une stack up-to-date (best in class crates, legeres), idiome rust natif (en particulier orienté fonctionnel)
6. **Low token optimization :**

### Rust Directives

#### Communication & Output
- Output code changes using standard UNIFIED DIFF (`diff -u`) or SEARCH/REPLACE blocks. Never dump full files.
- Be strictly technical, concise, no conversational filler.

#### Tooling & Validation Rules
- Validate incremental changes using `cargo check --message-format=short`.
- Ensure all code passes `cargo clippy --all-targets -- -D warnings`.
- Do not run full `cargo test`. Run specific tests using `cargo test <target>`.

#### Rust Coding Standards
- Modern Hyper: Use `hyper 1.x`, `hyper-util`, and `http-body-util`. Never use deprecated `hyper::Server` (0.14).
- Error Handling: Zero `unwrap()` or `expect()` in runtime code. Use `thiserror` for module errors and `?` propagation.
- Concurrency: Rely on `Arc<T>`, `arc-swap`, and `tokio::sync`. Keep async locks short and non-blocking across network I/O.
- Memory & Performance: Use zero-copy primitives (`bytes::Bytes`, borrowed slices where appropriate). Avoid unnecessary `.clone()` calls on large payloads.
- Modularity: Keep modules focused and under 250 LOC. Expose clean Tower `Layer`/`Service` interfaces for middleware components.
