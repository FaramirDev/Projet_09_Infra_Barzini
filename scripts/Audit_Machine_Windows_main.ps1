<#
.SYNOPSIS
    Script d'Audit de Conformite Workstation - Barzini Local
.DESCRIPTION
    - Audit Global : Detection et Desinstallation (Machine + Sessions Utilisateurs).
    - Audit Utilisateur : Conformite departement avec precision Machine/Session.
    - Format : ASCII (Textes ecrits sans accents natifs).
.AUTHOR
    PowerShell Architect for Barzini Corp
.DATE
    2026-02-19
.VERSION
    10.0 - Ajout du scan profond HKCU (NTUSER.DAT) pour detecter les installations par Session
#>


# ==========================================
# PARAMETRES DYNAMIQUES (Envoyes par Ansible)
# ==========================================
param (
    [Parameter(Mandatory=$true)]
    [string]$SharePathData,  # Ex: \\SRV-BARZINI-AD\ANSIBLE$

    [Parameter(Mandatory=$true)]
    [string]$SharePathReport # Ex: \\SRV-BARZINI-AD\ANSIBLE$\[TEMP]Rapport_AnsibleLog_20260219-1030
)

$PathCSV_Verte = Join-Path -Path $SharePathData -ChildPath "Data\ListeVertDepartements_Barzini.csv"
$PathCSV_Rouge = Join-Path -Path $SharePathData -ChildPath "Data\ListeRouge_Barzini.csv"
$ReportDir = $SharePathReport

$ErrorActionPreference = "Continue"
$Script:ExitCode = 0

# ==========================================
# VERIFICATION DES PRIVILEGES ADMINISTRATEUR
# ==========================================
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ERREUR CRITIQUE] Ce script doit absolument etre execute en tant qu'Administrateur pour auditer les sessions !" -ForegroundColor Red
    Exit
}

# ==========================================
# 1. FONCTIONS UTILITAIRES
# ==========================================

function Get-MachineSoftwareList {
    # Lit les logiciels installes au niveau de la MACHINE entiere (HKLM)
    $UninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    $SoftList = @()
    foreach ($key in $UninstallKeys) {
        if (Test-Path $key) {
            Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                $Props = Get-ItemProperty -Path $_.PSPath
                if ($Props.DisplayName) {
                    $SoftList += [PSCustomObject]@{
                        Name            = $Props.DisplayName
                        Version         = $Props.DisplayVersion
                        Publisher       = $Props.Publisher
                        UninstallString = $Props.UninstallString
                        QuietUninstall  = $Props.QuietUninstallString
                        Scope           = "Machine"
                    }
                }
            }
        }
    }
    return $SoftList | Sort-Object Name -Unique
}

function Get-UserSoftwareList {
    param([string]$SID, [string]$LocalPath)
    # Lit les logiciels installes au niveau d'une SESSION specifique (HKCU / NTUSER.DAT)
    
    $SoftList = @()
    $IsLoadedByScript = $false
    $HkuPath = "Registry::HKEY_USERS\$SID"
    
    # Si l'utilisateur n'est pas connecte, sa ruche n'est pas chargee. On la monte manuellement.
    if (-not (Test-Path $HkuPath)) {
        $NtUserDat = Join-Path $LocalPath "NTUSER.DAT"
        if (Test-Path $NtUserDat -ErrorAction SilentlyContinue) {
            $regArgs = "load `"HKU\$SID`" `"$NtUserDat`""
            $process = Start-Process -FilePath "reg.exe" -ArgumentList $regArgs -Wait -NoNewWindow -PassThru
            if ($process.ExitCode -eq 0) { $IsLoadedByScript = $true } else { return $SoftList }
        } else {
            return $SoftList
        }
    }
    
    $UninstallKey = "$HkuPath\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $UninstallKey) {
        Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty -Path $_.PSPath
            if ($Props.DisplayName) {
                $SoftList += [PSCustomObject]@{
                    Name            = $Props.DisplayName
                    Version         = $Props.DisplayVersion
                    Publisher       = $Props.Publisher
                    UninstallString = $Props.UninstallString
                    QuietUninstall  = $Props.QuietUninstallString
                    Scope           = "Session"
                }
            }
        }
    }
    
    # Nettoyage : On demonte la ruche si c'est nous qui l'avons montee
    if ($IsLoadedByScript) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$SID`"" -Wait -NoNewWindow | Out-Null
    }
    
    return $SoftList | Sort-Object Name -Unique
}

function Uninstall-BadSoftware {
    param([string]$Name, [string]$UninstallString, [string]$QuietString, [string]$Scope)
    
    Log-Write "   [ACTION] Tentative de desinstallation de : $Name (Cible: $Scope)..."
    $Cmd = if (-not [string]::IsNullOrWhiteSpace($QuietString)) { $QuietString } else { $UninstallString }

    if ([string]::IsNullOrWhiteSpace($Cmd)) {
        Log-Write "   [ECHEC] Pas de commande de desinstallation trouvee."
        return
    }

    try {
        if ($Cmd -match "msiexec") {
            if ($Cmd -match "\/I") { $Cmd = $Cmd -replace "\/I", "/X" }
            $Arguments = "$($Cmd -replace 'msiexec.exe','' -replace 'msiexec','') /qn /norestart"
            Start-Process "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow
            Log-Write "   [INFO] Commande MSI executee."
        } else {
            # CORRECTION : Utilisation de cmd.exe pour parser correctement les guillemets et les arguments natifs du Registre
            $Arguments = "/c `"$Cmd /S /SILENT /Q`""
            $Process = Start-Process -FilePath "cmd.exe" -ArgumentList $Arguments -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
            if ($Process) { $Process.WaitForExit(30000) }
            Log-Write "   [INFO] Commande de desinstallation silencieuse executee via CMD."
        }
    } catch {
        Log-Write "   [ERREUR] Echec lors de la desinstallation : $_"
    }
}

function Get-ActiveDirectoryDepartment {
    param([string]$SamAccountName)
    if (Get-Module -ListAvailable ActiveDirectory) {
        try { return (Get-ADUser -Identity $SamAccountName -Properties Department).Department } catch { return "UNKNOWN_AD_ERROR" }
    } else { return "AD_MODULE_MISSING" }
}

# ==========================================
# 2. INITIALISATION & VARIABLES
# ==========================================

$DateObj = Get-Date
$DateStr = $DateObj.ToString("yyyyMMdd-HHmm")
$NomMachine = $env:COMPUTERNAME
$ReportBuffer = [System.Text.StringBuilder]::new()

function Log-Write {
    param([string]$Message)
    Write-Host $Message
    [void]$ReportBuffer.AppendLine($Message)
}

# ==========================================
# 3. AUDIT DE LA MACHINE & COLLECTE DONNEES
# ==========================================

Log-Write "================= RAPPORT D'AUDIT ================="
Log-Write "Date Audit      : $DateStr"
Log-Write "Nom Machine     : $NomMachine"
Log-Write "Domaine Cible   : barzini.local"
Log-Write "---------------------------------------------------"

# --- Disques ---
try {
    $Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    foreach ($disk in $Disks) {
        $TotalGB = [math]::Round($disk.Size / 1GB, 2)
        $FreeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        Log-Write "Disque [$($disk.DeviceID)] Total: $TotalGB GB | Libre: $FreeGB GB"
    }
} catch { Log-Write "Erreur Audit Disque." }

$Sessions = Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty UserName
Log-Write "Session Active actuelle : $Sessions"

# Chargement CSV
if (Test-Path $PathCSV_Rouge) { $ListeRouge = Import-Csv $PathCSV_Rouge } else { Log-Write "[ERREUR] CSV Rouge introuvable !"; $ListeRouge = @() }
if (Test-Path $PathCSV_Verte) { $ListeVerte = Import-Csv $PathCSV_Verte } else { Log-Write "[ERREUR] CSV Vert introuvable !"; $ListeVerte = @() }

# Collecte Globale des logiciels
$MachineSoftwares = Get-MachineSoftwareList
$Profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Special -eq $false }

# ==========================================
# 4. AUDIT GLOBAL & REMEDIATION (LISTE ROUGE)
# ==========================================

Log-Write "`n---------------------------------------------------"
Log-Write "[AUDIT GLOBAL] Logiciels Interdits (Detection & Suppression)"
$StatusGlobal = 0 

# On audite la machine
foreach ($Soft in $MachineSoftwares) {
    foreach ($RedItem in $ListeRouge) {
        if ($Soft.Name -match $RedItem.Logiciel) {
            $StatusGlobal = 1
            Log-Write " [!!!] ALERTE ROUGE : Logiciel Interdit detecte -> $($Soft.Name) [Installe sur : Machine]"
            Uninstall-BadSoftware -Name $Soft.Name -UninstallString $Soft.UninstallString -QuietString $Soft.QuietUninstall -Scope "Machine"
        }
    }
}

# On audite les sessions en arriere-plan pour la liste rouge
foreach ($Prof in $Profiles) {
    $UserApps = Get-UserSoftwareList -SID $Prof.SID -LocalPath $Prof.LocalPath
    foreach ($Soft in $UserApps) {
        foreach ($RedItem in $ListeRouge) {
            if ($Soft.Name -match $RedItem.Logiciel) {
                $StatusGlobal = 1
                Log-Write " [!!!] ALERTE ROUGE : Logiciel Interdit detecte -> $($Soft.Name) [Installe sur : Session SID $($Prof.SID)]"
                Uninstall-BadSoftware -Name $Soft.Name -UninstallString $Soft.UninstallString -QuietString $Soft.QuietUninstall -Scope "Session"
            }
        }
    }
}

if ($StatusGlobal -eq 0) { Log-Write "[OK] Aucun logiciel interdit detecte (Ni sur la Machine, ni dans les Sessions)." }

# ==========================================
# 5. AUDIT UTILISATEURS DOMAINE (LISTE VERTE)
# ==========================================

Log-Write "`n---------------------------------------------------"
Log-Write "[AUDIT PROFILS] Conformite Utilisateurs Domaine barzini.local"

$UserAuditedCount = 0
$StatusUser = 0

foreach ($Prof in $Profiles) {
    try {
        $ObjSID = New-Object System.Security.Principal.SecurityIdentifier($Prof.SID)
        $FullUserName = $ObjSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $FullUserName = "Inconnu ($($Prof.SID))"
    }

    if ($FullUserName -match "BARZINI") {
        $ShortName = $FullUserName -replace ".*\\" 

        # EXCLUSIONS
        if ($ShortName -match "^(?i)(Administrateur|Administrator)$") {
            Log-Write "`n--- Audit Profil : $FullUserName ---"
            Log-Write " [EXCLUSION] utilisateurs administrateurs"
            continue
        }
        if ($ShortName -match "^(?i)ansible\.service$") {
            Log-Write "`n--- Audit Profil : $FullUserName ---"
            Log-Write " [EXCLUSION] Utilisateurs du service Ansible"
            continue
        }

        $UserAuditedCount++
        Log-Write "`n--- Audit Profil : $FullUserName ---"
        
        $UserDept = Get-ActiveDirectoryDepartment -SamAccountName $ShortName
        if ($UserDept -match "ERROR" -or [string]::IsNullOrWhiteSpace($UserDept)) { $UserDept = "UNKNOWN" }

        # Construction du nom de groupe (GG_U_XXX)
        $GroupDept = if ($UserDept -ne "UNKNOWN" -and $UserDept -notmatch "^GG_U_") { "GG_U_$UserDept" } else { $UserDept }
        
        Log-Write "Departement AD : $UserDept (Mappe en : $GroupDept)"

        # On recupere les logiciels specifiques a cet utilisateur (Sa session + La machine entiere)
        $UserSpecificApps = Get-UserSoftwareList -SID $Prof.SID -LocalPath $Prof.LocalPath
        $EffectiveSoftwares = $MachineSoftwares + $UserSpecificApps

        $Violations = @()
        foreach ($Soft in $EffectiveSoftwares) {
            $MatchRegle = $ListeVerte | Where-Object { $Soft.Name -like "*$($_.Logiciel)*" }
            if ($MatchRegle) {
                $AllowedDepts = $MatchRegle.Departements -split ","
                if (!($AllowedDepts -contains $GroupDept) -and !($AllowedDepts -contains "GG_U_ALL")) {
                    $StatusUser = 1
                    
                    # Amelioration du message selon le contexte (Machine ou Session)
                    if ($Soft.Scope -eq "Machine") {
                        $Violations += "$($Soft.Name) [Scope: MACHINE] -> AVERTISSEMENT : Logiciel global accessible a ce profil non-autorise (Risque machine partagee. Action IT : Restreindre via AppLocker ou reinstaller en 'Per-User')."
                    } else {
                        $Violations += "$($Soft.Name) [Scope: SESSION] -> INFRACTION : Logiciel installe directement dans la session personnelle de cet utilisateur."
                    }
                }
            }
        }

        if ($Violations.Count -gt 0) {
            Log-Write " [REFUSE] Logiciels non conformes au departement de cet utilisateur :"
            foreach ($v in $Violations) { Log-Write "   - $v" }
        } else {
            Log-Write " [OK] Logiciels conformes aux droits de ce departement."
        }
    }
}

if ($UserAuditedCount -eq 0) { Log-Write "Aucun profil utilisateur standard du domaine 'BARZINI' a auditer sur ce poste." }

# ==========================================
# 6. FINALISATION & EXPORT
# ==========================================

$FinalStatusFile = if ($StatusGlobal -eq 1 -or $StatusUser -eq 1) { "REFUSE-ALERTE" } else { "OK" }

# 1. Utilisation de -LiteralPath pour interdire a PS de lire les crochets de [TEMP]
if (-not (Test-Path -LiteralPath $ReportDir)) { 
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null 
}

$FileName = "[$FinalStatusFile]${NomMachine}_LogAnsible_${DateStr}.txt"

# 2. Remplacement de Join-Path par une simple concaténation pour eviter le bug des crochets
$FullPath = "$ReportDir\$FileName"

Log-Write "`nFin de l'audit."
Write-Host "Tentative d'ecriture vers : $FullPath"

try {
    # 3. Utilisation stricte de LiteralPath pour l'export
    $ReportBuffer.ToString() | Out-File -LiteralPath $FullPath -Encoding ASCII -Force
    Write-Host "`n[SUCCES] Rapport genere : $FullPath" -ForegroundColor Green
} catch {
    Write-Host "`n[ERREUR CRITIQUE] Impossible d'ecrire le rapport : $($_.Exception.Message)" -ForegroundColor Red
}