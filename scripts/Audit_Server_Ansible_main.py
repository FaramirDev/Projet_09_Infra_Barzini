###### CARTOUCHE ###
## SCRIPT PYTHON Pour Audit du Serveur Linux Ansible
## Auteur : Alexis R - Administrateur
## Version : v1.1
## Date : 04/03/2026
## Description : Audit de Securite des Fichiers Critiques - Permission 
######
#!/usr/bin/env python3

import os
import stat
import pwd
from datetime import datetime

# ==========================================
# 1. CONFIGURATION
# ==========================================
# nom de ton utilisateur Linux pour le srv ansible 'user-ansible' 
USER = "user-ansible"

# Le dossier où sera écrit le rapport
REPORT_DIR = f"/home/{USER}/scripts/rapports"

# Liste des fichiers critiques et des permissions MAXIMALES tolérées (en octal)
# Format : (Chemin, Permission_Max_Tolérée, Propriétaire_Attendu)
CRITICAL_TARGETS = [
    ("/etc/shadow", "0640", "root"),
    (f"/home/{USER}/.ssh", "0700", USER),
    (f"/home/{USER}/.ssh/id_rsa", "0600", USER),
    ("/etc/ansible/ansible.cfg", "0644", "root"),
    
]

# ==========================================
# 2. INITIALISATION
# ==========================================
timestamp = datetime.now().strftime("%Y%m%d-%H%M")
report_file = os.path.join(REPORT_DIR, f"Security_Audit_{timestamp}.txt")
alerts = []
logs = []

def write_log(message, is_alert=False):
    print(message)
    logs.append(message)
    if is_alert:
        alerts.append(message)

# Création du dossier de rapport s'il n'existe pas
try:
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)
except Exception as e:
    print(f"[ERREUR FATALE] Impossible de créer le dossier de rapport : {e}")
    exit(1)

# ==========================================
# 3. AUDIT DES PERMISSIONS
# ==========================================
write_log("================= AUDIT DE SECURITE ANSIBLE =================")
write_log(f"Date d'exécution : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
write_log("-------------------------------------------------------------")

for path, expected_perm, expected_owner in CRITICAL_TARGETS:
    try:
        # Récupedes infos du fichier
        file_stat = os.stat(path)
        
        # Extract de la permission en format octal (ex: '0644')
        actual_perm = oct(stat.S_IMODE(file_stat.st_mode)).zfill(4)
        
        # Récup du nom du propriétaire
        actual_owner = pwd.getpwuid(file_stat.st_uid).pw_name

        # Vérification 1 : Les permissions
        if actual_perm > expected_perm:
            write_log(f"[ALERTE ROUGE] Permissions trop larges sur {path} ! Actuel: {actual_perm} | Attendu: {expected_perm} max", is_alert=True)
        else:
            write_log(f"[OK] Permissions correctes sur {path} ({actual_perm})")

        # Vérification 2 : Le propriétaire
        if actual_owner != expected_owner:
            write_log(f"[ALERTE ROUGE] Propriétaire incorrect sur {path} ! Actuel: {actual_owner} | Attendu: {expected_owner}", is_alert=True)
        else:
            write_log(f"[OK] Propriétaire correct sur {path} ({actual_owner})")

    except FileNotFoundError:
        write_log(f"[INFO] Le fichier {path} n'existe pas (Ignoré).")
    except PermissionError:
        write_log(f"[ERREUR] Accès refusé pour lire les métadonnées de {path}. Exécutez le script avec sudo.", is_alert=True)
    except Exception as e:
        write_log(f"[ERREUR] Erreur inattendue sur {path} : {e}", is_alert=True)

# ==========================================
# 4. GENERATION DU RAPPORT
# ==========================================
write_log("-------------------------------------------------------------")
if len(alerts) > 0:
    write_log(f"RESULTAT FINAL : ECHEC - {len(alerts)} ALERTE(S) DETECTEE(S)")
else:
    write_log("RESULTAT FINAL : SUCCES - Le serveur est sécurisé.")

try:
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))
    print(f"\n[SUCCES] Rapport sauvegardé dans : {report_file}")
except Exception as e:
    print(f"\n[ERREUR] Impossible d'écrire le rapport final : {e}")
