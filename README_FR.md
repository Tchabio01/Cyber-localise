# CyberWatch Africa PRO 7.0 — Termux / Android

Plateforme locale de veille défensive et d'apprentissage SOC. Interface sombre cyberpunk, carte Afrique & monde, collecte de flux publics, investigation IP, découverte limitée du réseau privé, diagnostic Android, journal SQLite et exports.

## Nouveautés 5.0
- Cybermap continentale : affichage des IP géolocalisées, filtre Afrique / catégorie / recherche.
- Carte alimentée par des IP réellement présentes dans les flux publics collectés. Aucune route d'attaque fictive n'est dessinée.
- Tableau de bord SOC, état des sources, statistiques, top pays, historique et événements.
- Investigation d'IP publique, DNS inverse et correspondances avec les flux.
- Découverte LAN limitée au sous-réseau privé /24 détecté et ports TCP 22, 80, 443.
- Diagnostic de base du téléphone, DNS et Internet.
- Honeypot SSH expérimental facultatif, journal SQLite, notifications Termux et Telegram facultatives.
- Exports CSV / JSON et rapport imprimable en PDF via le navigateur.

## Installation Termux
1. Extrais le ZIP dans le stockage du téléphone.
2. Dans Termux, place-toi dans le dossier extrait, par exemple :
   ```bash
   cd ~/storage/downloads/CyberWatch_Africa_PRO_5
   ```
3. Exécute :
   ```bash
   chmod +x install_termux.sh start.sh
   ./install_termux.sh
   ./start.sh
   ```
4. Ouvre dans Chrome : `http://127.0.0.1:8080`.
5. Arrête le serveur avec `CTRL+C` dans Termux.

## Notifications Telegram (facultatif)
Avant `./start.sh`, configure les variables dans le terminal :
```bash
export TG_TOKEN="TON_TOKEN_BOT"
export TG_CHAT="TON_CHAT_ID"
```
Ne partage jamais ces valeurs. Elles ne sont pas enregistrées dans le ZIP.

## Honeypot (facultatif)
Désactivé par défaut. Pour l'activer sur un environnement que tu contrôles :
```bash
export CW_HONEYPOT=1
export CW_HONEYPOT_PORT=2222
./start.sh
```
Ne l'active pas sur un réseau public ou un appareil tiers. Il s'agit d'un listener de démonstration, pas d'un serveur SSH sécurisé.

## Configuration
- `CW_HOST` : `127.0.0.1` par défaut (conserve cette valeur pour un usage local).
- `CW_PORT` : `8080` par défaut.
- `CW_REFRESH` : intervalle de collecte en secondes (minimum 180).
- `CW_DB` : chemin facultatif de la base SQLite.
- `WATCH` : codes pays suivis pour les notifications, par défaut `CI,SN,GH,NG`. La carte et les statistiques couvrent tout le continent ; ce paramètre ne restreint pas l'affichage.

## Sources et limites
Flux publics Feodo Tracker, Blocklist.de et Emerging Threats. Les services externes peuvent être indisponibles, limiter les requêtes ou modifier leurs formats. Géolocalisation via ip-api : approximative et dépendante d'Internet. Une IP signalée dans un flux n'est pas nécessairement l'auteur d'une attaque et ne prouve pas qu'un appareil ou un pays est ciblé.

Le scan LAN est volontairement limité au réseau privé local. N'utilise les fonctions de découverte que sur des réseaux dont tu as l'autorisation. Ce logiciel est un outil de veille et de formation défensive ; il ne remplace ni un SOC professionnel, ni un pare-feu, ni un antivirus.

## Dépannage
- Port occupé : `export CW_PORT=8081` puis relance.
- Pas de flux : vérifie Internet et attends la première collecte ; les erreurs de source sont visibles dans le tableau.
- Carte vide : la carte et la géolocalisation nécessitent Internet ; les flux peuvent ne contenir aucune IP africaine pendant un cycle.
- Pour réinitialiser les données, arrête l'application puis supprime le fichier `~/cyberwatch_africa_v5.db` (cela efface l'historique).

## Modules CyberWatch 6.0
- CyberAI local : synthèse descriptive des statistiques et conseils prédéfinis, sans prétendre être une IA distante.
- Phishing Watch : analyse heuristique locale de l'URL, sans visiter le lien ni certifier sa sûreté.
- Protection Center : checklist et score pédagogique conservés dans le navigateur.
- Cyber Academy : missions, XP, badges et niveaux enregistrés localement.
- Alert Center : seuils de notifications configurables dans le navigateur.
- Africa Risk Index : classement du volume d'IP observées par pays, pas un indice de dangerosité nationale.
- Threat Timeline : chronologie des événements collectés.
- Langues : français, anglais, portugais et arabe (traduction partielle des titres).
- Export Intelligence : CSV, JSON et rapport imprimable déjà présents.
Les scores sont indicatifs. Ces modules ne remplacent ni un antivirus ni un SOC professionnel.

## CyberWatch Africa PRO 7.0 — plateforme multi-utilisateurs
- Authentification Supabase : inscription, connexion, déconnexion et profil.
- Organisations et équipes avec rôles owner, admin, analyst, member.
- Synchronisation cloud des observations locales réelles et événements, attribués au compte utilisateur.
- Console administrateur réservée au rôle défini dans les métadonnées sécurisées app_metadata.
- Politiques PostgreSQL Row Level Security (RLS) pour isoler les données par organisation.
- Aucun SOC Simulator, aucun faux incident et aucune donnée fictive.
- Les cartes affichent les localisations approximatives des IP observées ; elles ne fabriquent pas de destinations ou chemins d'attaque.

### Configuration Supabase
1. Appliquer supabase/schema.sql au projet Supabase choisi.
2. Définir CW_SUPABASE_URL et CW_SUPABASE_PUBLISHABLE_KEY sur le serveur. Ne jamais exposer une clé service_role.
3. Redémarrer CyberWatch et créer un compte puis une organisation.
4. Pour attribuer l'administration globale, définir app_metadata.platform_role=admin par un canal d'administration Supabase. Ne jamais utiliser user_metadata pour les autorisations.

**Sécurité importante :** ne publie pas directement le serveur Python actuel sur Internet. Ses API locales ne valident pas encore les JWT côté serveur et n'intègrent pas de reverse proxy HTTPS. Pour un déploiement public, il faudra terminer cette couche, activer HTTPS et configurer les règles réseau. La synchronisation cloud utilise RLS, mais cela ne protège pas à lui seul les routes locales.

Les observations synchronisées sont des contributions rapportées par un membre et ne sont pas automatiquement certifiées. Leur source et leur date restent visibles.
