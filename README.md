# CyberWatch Africa PRO 5.0

Plateforme locale de veille cyber et de supervision SOC orientée Afrique, conçue pour fonctionner sous Android avec Termux ou sur un environnement Python compatible.

## Fonctionnalités

- Tableau de bord SOC et statistiques de menaces.
- Collecte de flux publics : Feodo Tracker, Blocklist.de et Emerging Threats.
- Géolocalisation approximative des adresses IP et visualisation sur une carte africaine.
- Investigation d'une adresse IP publique.
- Inventaire réseau local limité au sous-réseau privé /24 et aux ports TCP 22, 80 et 443.
- Journal d'incidents, exports CSV/JSON et rapport imprimable.
- Diagnostic de l'environnement Termux.

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
- Les arcs lumineux de la carte sont des visualisations illustratives et ne prouvent pas une relation réelle entre une source et une cible.
- Le scan réseau doit être utilisé uniquement sur un réseau que vous possédez ou êtes autorisé à administrer.
- Le honeypot expérimental reste désactivé par défaut.

## Version

Voir le fichier `VERSION` pour la version de l'application.
