Import-Module ActiveDirectory

# --- CONFIGURATION ---
$parcPath = "C:\Users\Administrateur\Documents\Configuration\AD\data\referentiel_parc.csv"
$parcData = Import-Csv -Path $parcPath -Delimiter "," -Encoding UTF8

# Chemins des UO
$ouBase = "OU=BARZINI_STUDIOS,DC=barzini,DC=local"
$ouGroupes = "OU=Groupes,$ouBase"
$ouRacineParc = "OU=Parc,$ouBase"
$ouComputers  = "OU=Ordinateurs,$ouRacineParc"
$ouInfra      = "OU=Infrastructure,$ouRacineParc"
$ouMobiles    = "OU=Mobiles,$ouRacineParc"

# --- LOGS ---
$logFolder = "C:\Users\Administrateur\Documents\Configuration\AD\logs"
if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$logFile = "$logFolder\Log_Parc_AD_$timestamp.txt"

# --- LISTE BLANCHE ---
$osAutorises = @("Windows", "Linux", "Android", "iOS", "Infra")

# Variables pour le rapport
$listCreated = @()
$listUpdated = @()
$listGhosts = @()
$listNoOs = @() # Nouvelle liste pour les machines sans OS
$listErrors = @()
$parcCount = ($parcData).Count

# --- DEBUT DU TRAITEMENT ---
foreach ($item in $parcData) {
    $nomPoste = $item."Nom du poste".Trim()
    $loginUser = $item.Utilisateur.Trim()
    $typePoste = $item."Type de poste"
    $osMachine = if ($item.OS) { $item.OS.Trim() } else { $null }

    # 1. Sélection de l'OU
    $targetPath = $ouInfra
    if ($typePoste -match "PC|Fixe|Portable") { $targetPath = $ouComputers }
    elseif ($typePoste -match "Smartphone|Iphone|Android") { $targetPath = $ouMobiles }

    # 2. Audit Fantôme & ManagedBy (On le fait AVANT le test de l'OS)
    $managedByDN = $null
    $osLabel = if ($osMachine) { $osMachine } else { "NON RENSEIGNÉ" }
    $finalDescription = "OS: $osLabel | Type: $typePoste | GPU: $($item.'Carte graphique') | Service: $($item.'Date de mise en service')"

    if ($loginUser -and $loginUser -ne "N/A" -and $loginUser -ne "Libre") {
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$loginUser'" -ErrorAction SilentlyContinue
        if ($adUser) { 
            $managedByDN = $adUser.DistinguishedName 
        } else {
            $finalDescription = "⚠️ ALERTE AUDIT: Utilisateur inconnu ($loginUser) | " + $finalDescription
            $listGhosts += "Machine: $nomPoste | Utilisateur introuvable: $loginUser"
        }
    }

    # 3. Action AD
    try {
        $obj = Get-ADComputer -Filter "Name -eq '$nomPoste'" -ErrorAction SilentlyContinue
        if ($null -eq $obj) {
            New-ADComputer -Name $nomPoste -Path $targetPath -Description $finalDescription -Enabled $true -ManagedBy $managedByDN
            $listCreated += $nomPoste
        } else {
            Set-ADComputer -Identity $nomPoste -Description $finalDescription -ManagedBy $managedByDN
            if ($obj.DistinguishedName -notlike "*$targetPath*") {
                Move-ADObject -Identity $obj.DistinguishedName -TargetPath $targetPath
            }
            $listUpdated += $nomPoste
        }

        # 4. Gestion du Groupe OS (Seulement si OS valide)
        if ($osMachine -and $osMachine -in $osAutorises) {
            $groupM = if ($osMachine -eq "iOS") { "GG_M_IOS" } else { "GG_M_$osMachine" }
            if (-not (Get-ADGroup -Filter "Name -eq '$groupM'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $groupM -GroupCategory Security -GroupScope Global -Path $ouGroupes
            }
            Add-ADGroupMember -Identity $groupM -Members "$nomPoste$" -ErrorAction SilentlyContinue
        } else {
            # On stocke pour le rapport que cette machine n'a pas de groupe assigné
            $listNoOs += "$nomPoste (OS: $osLabel)"
        }

    } catch {
        $listErrors += "$nomPoste ($($_.Exception.Message))"
    }
}

# --- GÉNÉRATION DU BILAN ---
$report = @"
==========================================================
                SYNCHRONISATION DU PARC AD                
==========================================================
 Date : $((Get-Date -Format "dd/MM/yyyy HH:mm"))
 Source : $parcPath
 Total machines : $parcCount
----------------------------------------------------------

✅ NOUVELLES MACHINES ($($listCreated.Count)) :
$(if($listCreated.Count -gt 0){$listCreated -join "`r`n"}else{"(Aucune)"})

🔄 MISES À JOUR ($($listUpdated.Count)) :
$(if($listUpdated.Count -gt 0){$listUpdated -join "`r`n"}else{"(Aucune)"})

👻 ALERTES FANTÔMES ($($listGhosts.Count)) :
$(if($listGhosts.Count -gt 0){$listGhosts -join "`r`n"}else{"(Aucune)"})

⚠️ MACHINES SANS GROUPE OS ($($listNoOs.Count)) :
$(if($listNoOs.Count -gt 0){$listNoOs -join "`r`n"}else{"(Aucune)"})

❌ ERREURS TECHNIQUES ($($listErrors.Count)) :
$(if($listErrors.Count -gt 0){$listErrors -join "`r`n"}else{"(Aucune)"})

==========================================================
 Fin de traitement.
"@

Clear-Host
Write-Host $report -ForegroundColor Yellow
$report | Out-File -FilePath $logFile -Encoding UTF8
Write-Host "`n✅ Rapport d'audit enregistré : $logFile" -ForegroundColor Green