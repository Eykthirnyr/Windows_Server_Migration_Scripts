<#
.SYNOPSIS
    Importe les GPO depuis un dossier backup dans le domaine cible, en vérifiant
    et installant si nécessaire le module GroupPolicy (GPMC).

.DESCRIPTION
    1) Vérification si on est admin
    2) Vérification/Installation GPMC
    3) Import du module GroupPolicy
    4) Interaction pour le domaine cible, dossier backup
    5) Import GPO / Overwrite ou skip
    6) Résumé final

.NOTES
    Testé principalement sur Windows Server 2019/2022.
    Nécessite que le serveur ait accès aux sources pour installer la fonctionnalité GPMC.
#>

#region [1] VÉRIFICATION ÉLÉVATION (ADMIN)
Function Test-AdminRights {
    # Méthode simple : vérifier le groupe "Administrateurs" dans le token
    # (Compatible FR/EN sur la plupart des systèmes.)
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    return $isAdmin
}

if (-not (Test-AdminRights)) {
    Write-Host "[ERREUR] Vous devez exécuter ce script dans une console PowerShell 'En tant qu'administrateur'." -ForegroundColor Red
    return
}
#endregion

#region [2] INSTALLATION/CHARGEMENT DU MODULE GROUPPOLICY (GPMC)
Write-Host "Vérification de la fonctionnalité GPMC..."

try {
    # Vérifie d'abord si la commande 'Get-WindowsFeature' existe :
    if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        Write-Host "[AVERTISSEMENT] La commande Get-WindowsFeature n'est pas disponible. Vous n'êtes peut-être pas sur un Windows Server." -ForegroundColor Yellow
        Write-Host "Impossible d'installer GPMC automatiquement. Veuillez l'installer manuellement si nécessaire."
    }
    else {
        # On est sur Windows Server, on peut vérifier la présence de GPMC
        $gpmcFeature = Get-WindowsFeature GPMC
        if ($gpmcFeature -and $gpmcFeature.Installed -eq $false) {
            Write-Host "La fonctionnalité 'GPMC' n'est pas installée. Installation en cours..."
            Install-WindowsFeature GPMC -IncludeManagementTools -ErrorAction Stop
        }
        else {
            Write-Host "La fonctionnalité 'GPMC' est déjà installée."
        }
    }
}
catch {
    Write-Host "[ERREUR] Échec lors de l'installation ou la vérification de GPMC : $($_.Exception.Message)" -ForegroundColor Red
    return
}

try {
    # Import du module GroupPolicy
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Host "[ERREUR] Le module GroupPolicy n'a pas pu être importé : $($_.Exception.Message)" -ForegroundColor Red
    return
}
#endregion

Write-Host "`n====================================================="
Write-Host "  IMPORT DES GPO DANS LE DOMAINE CIBLE              "
Write-Host "====================================================="

#region [3] DEMANDE INFOS DOMAINE CIBLE + DOSSIER BACKUP
$TargetDomainController = Read-Host "Entrez le DC cible (ex: NewDC01.newdomain.local)"
$TargetDomainName       = Read-Host "Entrez le domaine cible (ex: newdomain.local)"
$BackupPath             = Read-Host "Entrez le chemin où se trouvent les GPO backupées (ex: C:\GPOBackups)"

if (-not (Test-Path $BackupPath)) {
    Write-Host ("[ERREUR] Le chemin '{0}' n'existe pas. Vérifiez que le dossier est correct." -f $BackupPath) -ForegroundColor Red
    return
}

Write-Host ("`nLecture des backups GPO dans '{0}'..." -f $BackupPath)
#endregion

#region [4] LECTURE DES BACKUPS & IMPORT
try {
    $allBackups = Get-GPOBackup -All -Path $BackupPath
}
catch {
    Write-Host ("[ERREUR] Impossible de lire les backups : {0}" -f $_.Exception.Message) -ForegroundColor Red
    return
}

if (-not $allBackups -or $allBackups.Count -eq 0) {
    Write-Host "Aucune GPO backupée détectée dans ce dossier. Script interrompu."
    return
}

Write-Host ("Nombre de GPO backupées détectées : {0}" -f $allBackups.Count)

# Variables pour stats
$importedCount = 0
$skippedCount  = 0
$errorCount    = 0

foreach ($bkInfo in $allBackups) {
    $gpoName  = $bkInfo.DisplayName
    $backupId = $bkInfo.BackupId

    Write-Host ("`nImport de la GPO : {0}" -f $gpoName)

    # Vérifier si une GPO du même nom existe déjà dans le domaine cible
    $existing = Get-GPO -All -Domain $TargetDomainName -Server $TargetDomainController |
                Where-Object { $_.DisplayName -eq $gpoName }

    if ($existing) {
        Write-Host ("Une GPO nommée '{0}' existe déjà dans le domaine cible." -f $gpoName)
        $choice = Read-Host "Voulez-vous l'écraser (I) ou la sauter (S) ? [I/S]"
        if ($choice -eq 'I' -or $choice -eq 'i') {
            Write-Host "Ecrasement (import) de la GPO existante..."
            try {
                Import-GPO -BackupId $backupId -Path $BackupPath `
                           -Domain $TargetDomainName -Server $TargetDomainController `
                           -TargetGuid $existing.Id `
                           -ErrorAction Stop
                $importedCount++
            }
            catch {
                Write-Host ("[ERREUR] Echec de l'import pour {0} : {1}" -f $gpoName, $_.Exception.Message) -ForegroundColor Red
                $errorCount++
            }
        }
        else {
            Write-Host "On saute la GPO '$gpoName'."
            $skippedCount++
        }
    }
    else {
        # Créer une nouvelle GPO dans le domaine cible
        try {
            Import-GPO -BackupId $backupId -Path $BackupPath `
                       -Domain $TargetDomainName -Server $TargetDomainController `
                       -CreateNew -ErrorAction Stop
            $importedCount++
        }
        catch {
            Write-Host ("[ERREUR] Echec de l'import (CreateNew) pour {0} : {1}" -f $gpoName, $_.Exception.Message) -ForegroundColor Red
            $errorCount++
        }
    }
}
#endregion

#region [5] RÉSUMÉ FINAL
Write-Host "`n====================================================="
Write-Host "          RÉSUMÉ DE L'IMPORT DES GPO                 "
Write-Host "====================================================="

Write-Host ("Total backups GPO détectés : {0}" -f $allBackups.Count)
Write-Host ("GPO importées              : {0}" -f $importedCount)
Write-Host ("GPO sautées                : {0}" -f $skippedCount)
Write-Host ("Erreurs d'import           : {0}" -f $errorCount)

Write-Host "`nFin de l'import GPO."
#endregion