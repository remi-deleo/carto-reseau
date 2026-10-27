# Carto réseau maison

Script PowerShell qui cartographie un réseau domestique avec **nmap** et signale ce qui change : nouvel appareil, port ouvert inattendu, appareil connu absent.

Projet d'apprentissage réalisé dans le cadre de ma reconversion vers le support informatique puis la cybersécurité.

## Ce que fait le script

1. Détecte automatiquement le réseau de la connexion active (adresse IP et masque, par exemple `192.168.1.0/24`).
2. Lance nmap : découverte des appareils et scan des 1 000 ports TCP les plus courants.
3. Compare le résultat avec une liste d'appareils de confiance (`appareils-connus.csv`), par adresse MAC puis par nom d'hôte.
4. Génère une page HTML datée dans `rapports/` et l'ouvre :
   - **rouge** : appareil jamais vu ;
   - **orange** : appareil connu avec un port ouvert qui n'est pas dans sa liste ;
   - **gris** : appareil connu absent du scan ;
   - les ports sensibles (SMB, RDP, Telnet, FTP, VNC…) sont encadrés, avec une explication au survol.

## Prérequis

- Windows 10 ou 11, PowerShell 5.1
- [nmap](https://nmap.org/download) avec Npcap
- Droits administrateur (nécessaires pour lire les adresses MAC)

## Utilisation

Dans PowerShell en administrateur, depuis le dossier du script :

```powershell
# Premier lancement : crée la liste des appareils connus à partir du réseau actuel
powershell -ExecutionPolicy Bypass -File .\carto.ps1 -Init

# Lancements suivants : scan et comparaison
powershell -ExecutionPolicy Bypass -File .\carto.ps1
```

Après l'initialisation, ouvrir `appareils-connus.csv` avec le Bloc-notes et donner un nom clair à chaque appareil. Format d'une ligne :

```
"Nom choisi";"AA:BB:CC:DD:EE:FF";"nom-hote.home";"80 443"
```

La dernière colonne liste les ports acceptés, séparés par des espaces.

## Ce que j'ai appris

- Lire une configuration IP (`ipconfig`) : adresse, masque, passerelle, notation CIDR `/24`
- La table ARP, les adresses de diffusion et de multidiffusion
- Les adresses MAC : identification du fabricant (OUI) et adresses aléatoires des téléphones
- Utiliser nmap : découverte (`-sn`), scan de ports, détection de services (`-sV`), export XML (`-oX`)
- Interpréter les états de ports (`open`, `closed`, `filtered`) et la réponse `tcpwrapped`
- Les limites d'un scan : photo à un instant donné, et un PC qui se scanne lui-même ne passe pas par son pare-feu
- PowerShell : calcul d'adresse réseau avec des masques binaires, lecture de XML, génération de HTML
- Démarche de sécurité : établir une référence, valider chaque appareil un par un, fermer ce qui ne sert pas

## Règle d'usage

À utiliser uniquement sur un réseau qui vous appartient ou avec une autorisation écrite. Scanner un réseau tiers sans autorisation peut constituer une tentative d'intrusion.

## Confidentialité

La liste des appareils et les rapports contiennent des informations sur le réseau personnel : ils sont exclus du dépôt par le fichier `.gitignore`.
