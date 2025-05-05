# 📘 Support de cours – **Spring Security**


## 🧭 Objectifs pédagogiques

À l’issue de ce cours, vous serez capable de :

* Comprendre les **fondamentaux de la sécurité des applications web**.
* Configurer et utiliser **Spring Security** *(bibliothèque Java spécialisée dans la sécurité)*.
* Implémenter l’**authentification** *(vérification de l’identité d’un utilisateur)*.
* Mettre en place l’**autorisation** *(gestion des permissions d’accès)*.
* Sécuriser des **API REST** *(Application Programming Interface utilisant les principes REST : sans état, client/serveur, etc.)*.
* Utiliser les **JWT (JSON Web Tokens)** *(jetons numériques signés pour représenter un utilisateur authentifié sans session)*.
* Appliquer des protections contre les attaques **XSS (Cross-Site Scripting)**, **CSRF (Cross-Site Request Forgery)**, et **Session Hijacking** *(vol de session utilisateur)*.

---

## I. 🔐 Introduction à la sécurité web

### 1.1 Pourquoi sécuriser une application ?

Une application non sécurisée peut :

* Permettre le **vol d’identifiants** ou de **données sensibles**.
* Être détournée pour des attaques sur d'autres systèmes.
* Exposer son éditeur à des **risques juridiques** (notamment le **RGPD** : *Règlement Général sur la Protection des Données*).

### 1.2 Exemples de menaces

* **Injection SQL** (*injection de code malveillant dans une requête base de données*).
* **XSS (Cross-Site Scripting)** (*injection de script malveillant dans une page web*).
* **CSRF (Cross-Site Request Forgery)** (*usurpation d’identité via une requête non légitime émise par un navigateur*).
* **Brute Force Attack** (*attaque par force brute pour deviner un mot de passe*).
* **Session Hijacking** (*vol de l’identifiant de session pour usurper une connexion*).

---

## II. 🧱 Qu’est-ce que **Spring Security** ?

### 2.1 Définition

**Spring Security** est un **framework** (*cadre logiciel*) de l’écosystème **Spring** (*plateforme Java pour créer des applications robustes et modulaires*) dédié à la **sécurité applicative**. Il fournit :

* L’**authentification** (*identification de l’utilisateur*),
* L’**autorisation** (*contrôle de l’accès aux ressources*),
* Des protections automatiques contre les attaques courantes (**CSRF**, **Session Fixation**, **XSS**, etc.).

---

## III. 🔧 Fonctionnement de Spring Security

### 3.1 Security Filter Chain (*chaîne de filtres de sécurité*)

* Une suite de **filtres HTTP** (*intercepteurs de requêtes*) appliqués dans un ordre précis.
* Exemples : `UsernamePasswordAuthenticationFilter`, `BasicAuthenticationFilter`.

### 3.2 SecurityContext (*contexte de sécurité*)

* Contient les **informations d’authentification** actuelles (utilisateur, rôles).
* Accessible dans toute l’application via `SecurityContextHolder`.

### 3.3 UserDetails et UserDetailsService

* **UserDetails** : interface représentant un **utilisateur authentifié**.
* **UserDetailsService** : interface à implémenter pour **charger les utilisateurs** (depuis une base de données, fichier, etc.).

---

## IV. 🔑 Authentification (Identification de l'utilisateur)

### 4.1 Types d’authentification dans Spring Security

* **Form Login** (*formulaire HTML de connexion*).
* **HTTP Basic Auth** (*identifiants envoyés dans les en-têtes HTTP*).
* **JWT (JSON Web Token)** (*jeton chiffré, signé et auto-contenu*).
* **OAuth2 (Open Authorization v2)** (*protocole d’authentification déléguée avec des fournisseurs comme Google, GitHub, etc.*).
* **LDAP (Lightweight Directory Access Protocol)** (*protocole d’accès aux services d’annuaire d’entreprise pour gérer les utilisateurs*).

### 4.2 PasswordEncoder

* Utilisé pour **hachage et vérification des mots de passe**.
* Exemples : **BCrypt** (*algorithme de hachage fort et sécurisé*), **PBKDF2**, **Argon2**.

---

## V. 🛂 Autorisation (contrôle d’accès)

### 5.1 Rôle et autorisation

* Les rôles sont des **étiquettes logiques** (ex : `ROLE_ADMIN`, `ROLE_USER`) attribuées à un utilisateur.
* L’autorisation se fait via :

  * **Les URL** (ex : `/admin/**` accessible uniquement aux `ADMIN`)
  * **Les annotations** (ex : `@PreAuthorize("hasRole('ADMIN')")`)

### 5.2 Annotations utiles

* `@Secured("ROLE_ADMIN")` : autorise uniquement les utilisateurs avec le rôle ADMIN.
* `@PreAuthorize` / `@PostAuthorize` : plus flexible, permet d’écrire des conditions avec **Spring Expression Language (SpEL)**.

---

## VI. 🔐 Sécurisation d’API REST

### 6.1 REST (Representational State Transfer)

* **Style architectural** pour les services web.
* Sans état (*stateless*) → **pas de session**, chaque requête doit contenir les informations de sécurité.

### 6.2 JWT (JSON Web Token)

* Jeton encodé en **Base64** contenant les données de l’utilisateur.
* Composé de trois parties : **header** (algorithme), **payload** (informations), **signature** (vérification).
* Permet une **authentification décentralisée**, sans session côté serveur.

---

## VII. ⚙️ Fonctions avancées de Spring Security

### 7.1 CSRF (Cross-Site Request Forgery)

* Attaque où un utilisateur connecté envoie une requête **à son insu**.
* Spring Security génère automatiquement un **token CSRF** à insérer dans chaque formulaire.

### 7.2 CORS (Cross-Origin Resource Sharing)

* Politique de sécurité du navigateur qui **bloque les requêtes entre domaines différents** (ex: frontend React sur `localhost:3000` vers backend Spring sur `localhost:8080`).
* Spring Security permet de configurer quels domaines sont autorisés à communiquer.

### 7.3 Session Management

* Gestion de la **session HTTP** utilisateur :

  * Limitation des sessions simultanées.
  * Expiration automatique.
  * Protection contre la **session fixation** (*vol d’identifiants de session*).

---

## VIII. 🌐 Intégration externe

### 8.1 LDAP (Lightweight Directory Access Protocol)

* Protocole standard pour **accéder à des annuaires utilisateurs** (ex : Active Directory).
* Utilisé pour connecter Spring Security à un **annuaire d’entreprise**.

### 8.2 OAuth2 / OpenID Connect

* **OAuth2** : permet à un utilisateur de s’authentifier via un fournisseur tiers (*Google, Facebook*).
* **OpenID Connect** : surcouche d’OAuth2 qui ajoute une **authentification standardisée**.
* Avantage : **pas besoin de stocker les mots de passe** dans l’application.

---

## IX. ✅ Bonnes pratiques de sécurité

* Toujours **encoder les mots de passe** avec **BCrypt** ou mieux.
* Activer la **protection CSRF** sauf pour les API REST.
* Protéger les **routes sensibles** avec des rôles spécifiques.
* Toujours valider les entrées utilisateur pour éviter les **XSS**, **injections**, etc.
* Utiliser **HTTPS** (HyperText Transfer Protocol Secure) pour chiffrer les communications.

---

## X. 🧪 Travaux pratiques recommandés (sans code)

1. **Analyser une route REST** et déterminer si elle est sécurisée.
2. **Lister les rôles d’utilisateurs** et les autorisations requises.
3. **Élaborer une stratégie d’authentification** avec ou sans session.
4. **Comparer les solutions OAuth2 vs JWT** dans un contexte d’API publique.
5. **Repérer les failles XSS/CSRF** sur un formulaire de connexion fictif.

---

## 📚 Annexes et ressources utiles

* 📘 Documentation officielle : [spring.io/security](https://spring.io/projects/spring-security)
* 🔐 JWT décodeur : [jwt.io](https://jwt.io)
* 🧱 Projet open-source Keycloak : [keycloak.org](https://www.keycloak.org)
* 🛡️ OWASP (Open Worldwide Application Security Project) : [owasp.org](https://owasp.org)
