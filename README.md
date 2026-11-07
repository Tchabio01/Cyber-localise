# CyberWatch Africa PRO 7.0

Plateforme locale de veille défensive et d'apprentissage SOC orientée Afrique, conçue pour fonctionner sous Android avec Termux ou sur un environnement Python compatible. L'application inclut des comptes et une synchronisation Supabase facultatifs ; cela ne transforme pas les routes de l'API locale en routes authentifiées.

## Fonctionnalités

- Tableau de bord SOC et statistiques de menaces.
- Collecte de flux publics : Feodo Tracker, Blocklist.de et Emerging Threats.
- Géolocalisation approximative des adresses IP et visualisation sur une carte africaine.
- Investigation d'une adresse IP publique.
- Inventaire réseau local limité au sous-réseau privé /24 et aux ports TCP 22, 80 et 443.
- Journal d'incidents, exports CSV/JSON et rapport imprimable.
- Diagnostic de l'environnement Termux.
- Plans de durcissement locaux pour appareils, réseaux Wi-Fi, comptes et serveurs.
- Comptes et synchronisation cloud Supabase facultatifs avec règles RLS.

## Installation sous Termux

Après avoir installé Termux :

```bash
pkg update -y
pkg install -y git python
git clone https://github.com/Tchabio01/Cyber-localise.git
cd Cyber-localise
```

Le code de l'application sera placé à la racine du dépôt. Pour la lancer :

```bash
chmod +x install_termux.sh start.sh
bash install_termux.sh
bash start.sh
```

Puis ouvrir http://127.0.0.1:8080 dans le navigateur du téléphone.

## Précautions

- Les flux publics sont des indicateurs de menace, pas une preuve qu'une machine a été compromise.
- La géolocalisation IP est approximative.
- Les données de menace et leur géolocalisation sont indicatives ; elles ne prouvent pas une compromission ni une relation entre une source et une cible.
- Le scan réseau doit être utilisé uniquement sur un réseau que vous possédez ou êtes autorisé à administrer.
- Le honeypot expérimental reste désactivé par défaut.
- Le serveur est limité à `127.0.0.1`. L'API locale ne vérifie pas les JWT Supabase ; ne l'expose pas sur un réseau. La protection locale ne remplace pas un système à jour et exempt de logiciels malveillants.
- Ne stockez pas de mots de passe, clés secrètes ou données sensibles dans les plans de protection du navigateur.

## Version

Voir le fichier `VERSION` pour la version de l'application.
