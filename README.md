# 🛡️ Industrialisation Parc Hybride & Strategie de Backup
## Automatisation & Security - Projet Studio Barzini

![Badge Ansible](https://img.shields.io/badge/Ansible-2.10+-black?style=for-the-badge&logo=ansible)
![Badge PowerShell](https://img.shields.io/badge/PowerShell-7.0-blue?style=for-the-badge&logo=powershell)
![Badge Python](https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python)
![Badge License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## ------ Présentation du Projet ------
Ce projet vise à moderniser, automatiser et sécuriser l'infrastructure hybride de l'entreprise **Barzini**. L'objectif est de passer d'une gestion manuelle à une approche **Infrastructure as Code (IaC)** tout en garantissant une résilience totale des données.

### ------ Objectifs Clés ------
* **Centralisation de l'Identité :** Déploiement d'un annuaire Active Directory (Modèle AGDLP).
* **Orchestration & Automatisation :** Gestion du parc mixte (Windows/Linux) via Ansible (Agentless).
* **Audit de Conformité :** Développement de scripts (PowerShell/Python) pour le monitoring des logiciels non autorisés et des permissions critiques.
* **Résilience & Cybersécurité :** Stratégie de sauvegarde 3-2-1-1-0 avec Veeam et chiffrement Zero-Knowledge via Cryptomator.

---

## ------ Architecture & Flux ------ 
L'infrastructure repose sur un serveur de contrôle Ansible (Ubuntu) communiquant via des flux sécurisés.

![Schema Architecture](/Captures/p9-Architecture_outpwd.jpg)

* **Gestion Windows :** WinRM via HTTPS (Port 5986).
* **Gestion Linux :** SSH (Port 22).
* **Stockage :** Partages SMB sécurisés pour la centralisation des rapports d'audit.

### ------ Tableau des Flux ------  


| Source | Destination | Protocole | Usage |
| -- | -- | -- | -- |
| Ansible | Linux | SSH - Port 22 | Gestion / Audit |
| Ansible | Windows | WinRM - Port 5986 | Gestion / Audit |
| Windows 11 | Active Directory | SMB - Port 445 | Dêpot / Partage |
| Veeam Server | VM Veeam | Agent | Sauvegarde Donnée |
| Toutes VMs | Veeam Repot | Data Transfer | Stockage Backup |
| Parc Hybrid | AD | UDP ( 53/123 ) | Résolution & Synchro |



---

## ------ Stack Technique ------ 
* **Systèmes :** Windows Server 2022 (AD DS), Windows 11, Ubuntu 22.04 LTS.
* **Automatisation :** Ansible (Playbooks, Vault, Roles).
* **Scripting :** PowerShell (Audit Windows), Python (Audit Linux / Shadow file).
* **Sauvegarde :** Veeam Backup & Replication.
* **Chiffrement :** AES-256 (Ansible Vault), Cryptomator.

---

## 🔒 ------ Focus Cybersécurité ------ 
1. **Modèle AGDLP :** Organisation stricte des groupes de sécurité pour respecter le principe du moindre privilège.
2. **Hardening Ansible :** Utilisation systématique d'**Ansible Vault** pour le chiffrement des secrets et certificats SSL pour WinRM.
3. **Audit de Conformité :** Scripts automatisés détectant les dérives de configuration (shadow file permissions) et la présence de logiciels interdits (Blacklisting).
4. **Protection des Données :** Implémentation du chiffrement côté client avant externalisation des sauvegardes.

---

## 📂 ------ Structure du Dépôt ------ 
```text
├── playbooks/            # Playbooks Ansible (Audit, Updates, Config)
├── scripts/              # Scripts d'audit (Python & PowerShell)
├── inventory/            # Inventaire hosts.ini (groupé par OS/Fonction)
├── docs/                 # Schémas et documentation technique
├── Captures/             # Captures Readme
└── README.md
```

---
## ------ SOMMAIRE ------ 
- [Partie 1 : Presentation Serveur Windows Active Directory](#-------partie-1---presentation-serveur-win-ad--identité--gouvernance-------)
    - [1. Gourvernace Annuaire - Data Driven](#1-gouvernance-de-lannuaire-data-driven-ad)
    - [2. Implementation Modele AGDLP](#2-implémentation-du-modèle-agdlp)
    - [3. Service de Partage - Permission NTFS](#3-service-de-fichiers--permissions-ntfs)
    - [4. Coffre Fort - Cryptomator & KeePass](#4-coffre-fort-numérique--cryptomator--keepass)

- [Partie 2 : Presenation Serveur Linux - Ansible](#-------partie-2--presentation-serveur-linux-ansible--orchestration--------)
    - [1. DEMO - Automatisation n°1 - Audit Parc Windows](#----demonstration-automatisation-n1-audit-des-machines-windows-via-serveur-ansible----)
    - [2. DEMO - Automatisation n°2 - Audit Serveur Ansible](#----demonstration-automatisation-n2---hardening-du-serveur-ansible-python----)
    - [3. DEMO - Automatisation n°3 - Mise à Jours Parc Hybride](#----demonstration-automatisation-n3---gestion-du-cycle-de-vie-patch-management----)
    
- [Partie 3 : Presentation Politique & Configuration de Sauvegarde - VEAAM](#-------partie-3--presentation--politique-de-sauvegarde---veeam-backup-------)
    - [1. Scenarios Restauration Critiques](#2-scénarios-de-restauration-critiques)
---
## ------ Presentation ------ 
![ Capture Annoncement Presenation AD](./Captures/Partie-01-AD/00-Presenation.png)
## ------ PARTIE 1 :  Presentation Serveur Win AD : Identité & Gouvernance ------ 
### 1. Gouvernance de l'Annuaire (Data-Driven AD)
Industrialisation de la gestion des objets via PowerShell pour garantir l'intégrité des données.

- **Provisioning Automatisé** : Script de création et de placement des utilisateurs dans les Unités d'Organisation (OU) cibles à partir d'un référentiel RH (CSV).

- **Audit d'Inventaire** : Script d'extraction automatisé du parc informatique et des comptes actifs pour un suivi précis des actifs (Asset Management).

![ Capture Data CSV Remonte](./Captures/Partie-01-AD/01_RemonteAD_USER_Parc.jpg)

![ Capture Log / Rapport AD](./Captures/Partie-01-AD/02_RemonteAD_USER_Parc.jpg)

### 2. Implémentation du Modèle AGDLP
Architecture des droits d'accès basée sur les meilleures pratiques Microsoft pour une scalabilité maximale.

- **Principe** : **A**ccounts ➔ **G**lobal Groups (Métiers) ➔ **D**omain **L**ocal Groups (Ressources) ➔ **P**ermissions.

![ Capture UO AD](./Captures/Partie-01-AD/03_UniteOrganisation.jpg)

![ Capture UO AD - Account](./Captures/Partie-01-AD/04_UniteOrganisation_Account.jpg)

![ Capture UO AD - Parc](./Captures/Partie-01-AD/04_UniteOrganisation_Parc.jpg)

![ Capture UO AD - Parc](./Captures/Partie-01-AD/04_UniteOrganisation_Group.jpg)

- **Exemple de flux** : Un **développeur** (`Account`) est membre du groupe métier `GG_U_DEV`. Pour accéder en lecture aux ressources graphiques, ce groupe est imbriqué dans le groupe de ressource `DL_GRAPH_R`, lequel détient les permissions **NTFS** de lecture.

### 3. Service de Fichiers & Permissions NTFS
- Mise en place de partages réseaux départementaux sécurisés.

- Gestion fine des accès via les groupes de ressources **DL** (Read / Read-Write), garantissant le respect du principe de **moindre privilège**.

### 4. Coffre-fort Numérique : Cryptomator & KeePass
Sécurisation des secrets et des données ultra-sensibles.

- **Cryptomator** : Chiffrement transparent (AES-256) des volumes de données avant stockage, avec une approche *Zero-Knowledge*.

- **KeePass** : Gestion centralisée des clés de déchiffrement et des mots de passe d'administration via une base de données chiffrée.

![Capture Cryptomator KeePass](./Captures/Partie-01-AD/05_Cryptomator.jpg)

---
![ Capture Annoncement Presenation AD](./Captures/Partie-02-Ansible/00-Presenatiion-2.png)

## ------ PARTIE 2 : Presentation Serveur Linux Ansible : Orchestration  ------ 
### 1. Architecture Infrastructure as Code (IaC)
Organisation modulaire du serveur Ansible (Inventaires dynamiques, `group_vars` chiffrés par **Vault**.)

### 2. Audit de Conformité Windows (PowerShell & Ansible)
Flux automatisé de détection des dérives logicielles.

- **Logique métier**: Déploiement d'un sript d'audit, de scan éphémère comparant l'inventaire local à deux référentiels :

    - ⚪ **ListeVerte** : Logiciels métier approuvés et versions minimales requises.

    - 🔴 **ListeRouge** : Logiciels prohibés (Risques de sécurité ou légaux).

- **Reporting** : Centralisation automatique des rapports d'audit `[OK]` ou `[REFUSE-ALERTE]` avec tentative de **Desinstallation** puis écriture du rapport sur le serveur de logs AD (`Ansible$`).

### --- Demonstration Automatisation n°1 Audit des Machines windows via Serveur Ansible --- 

Lors de la démonstration, nous avons renseigné dans la liste Rouge le Software `Canva` qui a été préablement installé sur la machine cible afin de démontré l'efficacité du Script d'Audit. 

**1. Schéma du Dérouler du Playbook :**
![Capture Demonstration Script audit 01 - 1](./Captures/Partie-02-Ansible/01-AuditWindows01.jpg)

**2. Lancement du Playbooks :** 
![Capture Demonstration Script audit 01 - 2](./Captures/Partie-02-Ansible/01-AuditWindows02.jpg)

**3. Rapport Detaillé de l'Audit :**
![Capture Demonstration Script audit 01 - 3](./Captures/Partie-02-Ansible/01-AuditWindows03.jpg)

### --- Demonstration Automatisation n°2 - Hardening du Serveur Ansible (Python) ---
Audit de sécurité interne du nœud de contrôle pour prévenir toute escalade de privilèges.

- **Vérification Python** : Analyse des permissions et des propriétaires `(root:root)` sur les fichiers critiques : `/etc/shadow`, clés privées `SSH`, et configurations `ansible.cfg`.

- **Objectif** : Garantir que le moteur d'orchestration ne soit pas un vecteur de compromission.

**1. Lancement & Résultat de l'Audit du Serveur Ansible :** 
![Capture Demonstration Audit Serveur Ansible](./Captures/Partie-02-Ansible/02-AuditAnsible01.jpg)

### --- Demonstration Automatisation n°3 - Gestion du Cycle de Vie (Patch Management) ---
Playbooks d'automatisation des mises à jour système (Windows Updates & Apt-Upgrade) avec gestion des redémarrages et vérification post-patching.

**1. Schéma du Dérouler du Playbook :**
![Capture Demonstration Mise A jours du Parc via Ansible 01](./Captures/Partie-02-Ansible/03-MiseAjours01.jpg)

**2. Lancement & Resultat du Playbooks :** 
![Capture Demonstration Mise A jours du Parc via Ansible 02](./Captures/Partie-02-Ansible/03-MiseAjours02.jpg)

---
![Capture Presenation Veeam Backup](/Captures/Partie-03-VeeamBackup/00-Presentation.png)
## ------ PARTIE 3 : Presentation  Politique de Sauvegarde - VEEAM Backup ------ 
### 1. Politique de Sauvegarde (BCP/DRP)
**Rédaction** d'une **Politique** de **Sauvegarde** avec un Plan de Continuité d'Activité incluant la règle du 3-2-1-1-0, disponible dans les **Livrables**.

### 2. Scénarios de Restauration Critiques
**Configuration & Démonstration** de la résilience de l'infrastructure à travers trois niveaux :

- **Scénario 1** : Restauration granulaire d'objets Active Directory ou de fichiers utilisateurs.

- **Scénario 2** : Restauration d'urgence via Instant VM Recovery.

- **Scénario 3** : Restauration complète après sinistre ( sur `Coffre Fort Cryptomator` )

![Capture Sommaire Documentation](./Captures/Partie-03-VeeamBackup/01-Sommaire.png)

## ------ Conclusion ------ 
Ce projet démontre une approche DevSecOps de l'administration système, où l'automatisation et la sécurité sont intégrées dès la conception. L'infrastructure est désormais résiliente, auditable et prête pour une mise en production industrialisée.

---
**Auteur** : Rousseau Alexis

**Rôle** : Administrateur Systèmes, Réseaux & Cybersécurité

**Date** : Fevrier 2026