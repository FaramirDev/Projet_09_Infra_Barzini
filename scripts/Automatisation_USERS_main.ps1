Import-Module ActiveDirectory

# --- CONFIGURATION ---
$csvPath = "C:\Users\Administrateur\Documents\Configuration\AD\data\utilisateurs.csv"
$userData = Import-Csv -Path $csvPath -Delimiter "," -Encoding UTF8
$defaultPassword = ConvertTo-SecureString "Barzini2026!" -AsPlainText -Force

# Chemins AD
$ouBase = "OU=BARZINI_STUDIOS,DC=barzini,DC=local"
$ouUsers = "OU=Utilisateurs,$ouBase"
$ouAnciens = "OU=Anciens_Collaborateurs,$ouUsers"

# --- CONFIGURATION LOG ---
$logFolder = "C:\Users\Administrateur\Documents\Configuration\AD\logs"
if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$logFile = "$logFolder\Log_Users_AD_$timestamp.txt"

# --- LISTE BLANCHE DES DÉPARTEMENTS ---
$ouAutorisees = @("Direction", "Developpement", "Graphisme", "IT", "Audio", "Test", "Production")

# Variables pour le rapport
$listCreated = @()
$listUpdated = @()
$listDisabled = @()
$listErrors = @()
$listFoldersPaths = @()
$csvUserCount = ($userData).Count

Write-Host "🚀 Démarrage de la synchronisation... Merci de patienter." -ForegroundColor Cyan

# --- DEBUT DU TRAITEMENT ---
foreach ($user in $userData) {
    
    # 1. Préparation des données
    $cleanNom = $user.Nom.Normalize("FormD") -replace '\p{M}', '' -replace '\s+',''
    $cleanNom = $cleanNom.ToLower()
    $cleanPrenomLetter = ($user.Prenom.Substring(0,1)).ToLower()
    $samAccountName = "$cleanPrenomLetter.$cleanNom"
    
    $depName = $user.Departement
    $description = "Fonction: $($user.Fonction) | Techno: $($user.Techno)"
    $email = ("$($user.Prenom.Trim()).$($user.Nom.Trim())@barzini.com" -replace '\s+','').ToLower()
    
    # --- VÉRIFICATION SÉCURITÉ : LISTE BLANCHE ---
    if ($user.Statut -ne "OFF" -and $depName -notin $ouAutorisees) {
        $listErrors += "$samAccountName (Département inconnu : $depName)"
        continue 
    }

    $targetOU = if ($user.Statut -eq "OFF") { $ouAnciens } else { "OU=$depName,$ouUsers" }

    # Vérification/Création de l'OU
    if ($user.Statut -ne "OFF" -and -not (Get-ADOrganizationalUnit -Filter "Name -eq '$depName'" -SearchBase $ouUsers -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $depName -Path $ouUsers
    }

    # Chemins Dossier Personnel
    $homeDrive = "Z:"
    $homeDirectory = "\\SRV-BARZINI-AD\Users$\$samAccountName"
    $physicalPath = "C:\Partages\Users\$samAccountName"

    # 2. Vérification de l'existence
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue

    if ($null -eq $adUser) {
        # --- CRÉATION ---
        $isEnabled = if ($user.Statut -eq "OFF") { $false } else { $true }
        try {
            New-ADUser -Name "$($user.Prenom) $($user.Nom)" `
                       -SamAccountName $samAccountName `
                       -UserPrincipalName "$samAccountName@barzini.local" `
                       -EmailAddress $email -Description $description `
                       -Path $targetOU -AccountPassword $defaultPassword `
                       -ChangePasswordAtLogon $isEnabled -Enabled $isEnabled `
                       -HomeDrive $homeDrive -HomeDirectory $homeDirectory
            
            Add-ADGroupMember -Identity "GG_U_All_Employees" -Members $samAccountName
            Add-ADGroupMember -Identity "GG_U_VPN_Acces" -Members $samAccountName
            
            $depGroup = "GG_U_$depName"
            if (-not (Get-ADGroup -Filter "Name -eq '$depGroup'")) {
                New-ADGroup -Name $depGroup -GroupCategory Security -GroupScope Global -Path "OU=Groupes,$ouBase"
            }
            Add-ADGroupMember -Identity $depGroup -Members $samAccountName
            $listCreated += $samAccountName
        } catch { $listErrors += "$samAccountName (Erreur AD)" }
    } 
    else {
        # --- MISE À JOUR ---
        Set-ADUser -Identity $samAccountName -Description $description -EmailAddress $email `
                   -Department $depName -HomeDrive $homeDrive -HomeDirectory $homeDirectory
        
        if ($user.Statut -eq "OFF") {
            Disable-ADAccount -Identity $samAccountName
            if ($adUser.DistinguishedName -notlike "*$ouAnciens*") {
                Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $ouAnciens
            }
            $listDisabled += $samAccountName
        } 
        else {
            Enable-ADAccount -Identity $samAccountName
            if ($adUser.DistinguishedName -notlike "*$targetOU*") {
                Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $targetOU
            }
            $depGroup = "GG_U_$depName"
            $currentMembers = Get-ADGroupMember -Identity $depGroup | Select-Object -ExpandProperty SamAccountName
            if ($samAccountName -notin $currentMembers) {
                Add-ADGroupMember -Identity $depGroup -Members $samAccountName
            }
            $listUpdated += $samAccountName
        }
    }

    # --- DOSSIER PHYSIQUE ---
    if ($user.Statut -ne "OFF" -and -not (Test-Path $physicalPath)) {
        try {
            New-Item -Path $physicalPath -ItemType Directory -Force | Out-Null
            $acl = Get-Acl $physicalPath
            $acl.SetAccessRuleProtection($true, $true)
            $ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule($samAccountName, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($ruleUser)
            $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateurs", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($ruleAdmin)
            Set-Acl $physicalPath $acl
            $listFoldersPaths += $physicalPath
        } catch { $listErrors += "$samAccountName (Erreur Dossier)" }
    }
}

# --- GÉNÉRATION DU BILAN FINAL ---
$report = @"
==========================================================
             SYNCHRONISATION UTILISATEURS AD              
==========================================================
 Date : $((Get-Date -Format "dd/MM/yyyy HH:mm"))
 Source : $csvPath
 Total traité : $csvUserCount ligne(s)
----------------------------------------------------------

🆕 NOUVEAUX UTILISATEURS ($($listCreated.Count)) :
$(if($listCreated.Count -gt 0){$listCreated -join "`r`n"}else{"(Aucun)"})

🔄 MISES À JOUR ($($listUpdated.Count)) :
$(if($listUpdated.Count -gt 0){$listUpdated -join "`r`n"}else{"(Aucun)"})

🔒 COMPTES DÉSACTIVÉS / OFF ($($listDisabled.Count)) :
$(if($listDisabled.Count -gt 0){$listDisabled -join "`r`n"}else{"(Aucun)"})

📂 DOSSIERS PERSONNELS CRÉÉS ($($listFoldersPaths.Count)) :
$(if($listFoldersPaths.Count -gt 0){$listFoldersPaths -join "`r`n"}else{"(Aucun)"})

❌ ERREURS / REJETÉS ($($listErrors.Count)) :
$(if($listErrors.Count -gt 0){$listErrors -join "`r`n"}else{"(Aucun)"})

==========================================================
 Fin de traitement.
"@

# Affichage Console
Clear-Host
Write-Host $report -ForegroundColor Cyan

# Enregistrement Log
$report | Out-File -FilePath $logFile -Encoding UTF8
Write-Host "`n✅ Log généré : $logFile" -ForegroundColor Green