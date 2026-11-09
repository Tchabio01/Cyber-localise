# NeuroBouclier Africa — MVP technique

## Objectif

Faire évoluer CyberWatch Africa PRO 7.0 en plateforme défensive, d'abord locale sur le poste de l'équipe fondatrice, puis multi-organisation via Supabase après validation de la sécurité.

## Modules de cette première livraison

| Module | Implémentation |
|---|---|
| Carte africaine | Réutilise Leaflet et les coordonnées issues des IP présentes dans les flux existants. Aucun trajet d'attaque n'est fabriqué. |
| Centre des incidents | Table SQLite `incidents` liée au journal `events`; statut ouvert/en cours/résolu, responsable et note de résolution. |
| Threat intelligence | Réutilise Feodo Tracker, Blocklist.de et Emerging Threats; conserve la provenance et les horodatages. |
| Multi-utilisateurs | Réutilise Supabase Auth, organisations, rôles et RLS; migration complémentaire pour le workflow d'incident et le catalogue CVE. |
| Vulnérabilités | Import à la demande du catalogue officiel CISA Known Exploited Vulnerabilities (KEV), validation du format CVE et conservation de la source. |
| Telegram | Réutilise le canal Telegram facultatif et ajoute un bouton de test sans exposer le jeton au navigateur. |

## Architecture

- Interface : HTML, CSS, JavaScript natif et Leaflet.
- API locale : serveur Python standard-library, lié exclusivement à `127.0.0.1`.
- Stockage local : SQLite; création/migration additive des tables au démarrage.
- Cloud : Supabase Auth + PostgreSQL RLS. Le client n'utilise que la clé publishable; aucune clé `service_role` ne doit être placée dans le navigateur ou dans Git.
- Source vulnérabilités : catalogue CISA KEV officiel, synchronisé manuellement. Les entrées ne signifient pas qu'un actif du client est vulnérable.

## Installation et vérification sous Windows / Git Bash

Depuis la racine du dépôt :

```bash
source .venv/Scripts/activate
python -m py_compile cyberwatch.py
python -m unittest discover -s tests -v
python -u cyberwatch.py
```

Ouvrir ensuite `http://127.0.0.1:8080`. Garder le terminal ouvert.

## Activer Telegram sous Windows / Git Bash

Créer un bot avec le canal de confiance, puis configurer les variables uniquement dans le terminal local :

```bash
export TG_TOKEN='COLLER_LE_JETON_LOCAL'
export TG_CHAT='COLLER_LE_CHAT_ID'
python -u cyberwatch.py
```

Utiliser le bouton « Tester Telegram ». Ne jamais transmettre le jeton dans une capture, un ticket, un commit ou un message. Le jeton ne doit pas être mis dans le JavaScript.

## Activer le cloud Supabase

1. Vérifier le projet Supabase choisi et ses sauvegardes.
2. Exécuter d'abord `supabase/schema.sql` si le schéma de base n'a jamais été appliqué.
3. Exécuter ensuite `supabase/migrations/20261109_neurobouclier_mvp.sql` dans le SQL Editor.
4. Définir `CW_SUPABASE_URL` et `CW_SUPABASE_PUBLISHABLE_KEY` dans l'environnement du serveur.
5. Redémarrer, créer un compte et une organisation, puis tester avec deux comptes de rôles différents.

Ne jamais utiliser une clé `service_role` dans le navigateur, le dépôt ou un fichier distribué.

## Limites et sécurité

- Le serveur local refuse toute écoute autre que `127.0.0.1`; ne pas le publier directement sur Internet.
- L'API SQLite locale n'est pas une API multi-tenant exposée au public. Le cloud Supabase applique ses propres contrôles RLS.
- Les indicateurs publics sont des signaux de renseignement, pas une preuve qu'un appareil ou un pays a été attaqué.
- La géolocalisation d'une IP est approximative et ne permet pas d'attribuer une attaque.
- Les vulnérabilités CISA KEV sont des vulnérabilités exploitées connues à l'échelle générale; elles ne prouvent pas qu'un système local est affecté.
- Les actions de remédiation doivent être examinées et validées par un responsable autorisé. Aucun blocage automatique n'est activé.
- Telegram est facultatif; limiter les messages aux métadonnées non sensibles.

## Prochaines étapes après ce MVP

1. Vérifier les tests et effectuer une collecte réelle sur le poste pilote.
2. Ajouter l'inventaire des actifs autorisés avant de corréler les CVE à un environnement client.
3. Ajouter les tests RLS avec plusieurs comptes et organisations.
4. Préparer une sauvegarde/restauration SQLite et Supabase.
5. Faire une revue de sécurité indépendante avant toute exposition réseau ou mise en production.
