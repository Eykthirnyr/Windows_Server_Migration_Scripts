<#
.SYNOPSIS
    Exporte toutes les GPO du domaine source vers un dossier local.
    A exécuter sur le domaine source.

.DESCRIPTION
    1) Import du module GroupPolicy
    2) Demande des infos (DC, domaine, dossier backup)
    3) Sauvegarde toutes les GPO
    4) Affiche un résumé

#>

Write-Host "====================================================="
Write-Host "  EXPORT DES GPO DU DOMAINE SOURCE                  "
Write-Host "====================================================="

# 1. Vérifier la disponibilité du module GroupPolicy
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Host "Le module 'GroupPolicy' n'est pas installé ou disponible. Installez RSAT ou utilisez un DC plus récent."
    return
}
Import-Module GroupPolicy -ErrorAction Stop

# 2. Demande des informations nécessaires
$SourceDomainController = Read-Host "Entrez le nom (ou FQDN) du DC source (ex: DC1.olddomain.local)"
$SourceDomainName       = Read-Host "Entrez le nom du domaine source (ex: olddomain.local)"
$BackupPath             = Read-Host "Entrez un chemin local pour stocker les backups (ex: C:\GPOBackups)"

# Créer le dossier s'il n'existe pas
if (-not (Test-Path $BackupPath)) {
    Write-Host ("Création du dossier de backup : {0}" -f $BackupPath)
    New-Item -ItemType Directory -Path $BackupPath | Out-Null
}

Write-Host "`nRécupération de toutes les GPO du domaine '$($SourceDomainName)'..."

# 3. Lister toutes les GPO du domaine source
try {
    $sourceGPOs = Get-GPO -All -Domain $SourceDomainName -Server $SourceDomainController -ErrorAction Stop
}
catch {
    Write-Host "[ERREUR] Impossible de lister les GPO : $($_.Exception.Message)" -ForegroundColor Red
    return
}

if (-not $sourceGPOs -or $sourceGPOs.Count -eq 0) {
    Write-Host "Aucune GPO trouvée dans le domaine '$($SourceDomainName)'. Script interrompu."
    return
}

Write-Host ("Nombre de GPO détectées : {0}" -f $sourceGPOs.Count)

# 4. Sauvegarder chaque GPO
$backupCount = 0
foreach ($gpo in $sourceGPOs) {
    Write-Host ("Backup GPO : {0}" -f $gpo.DisplayName)
    try {
        Backup-GPO -Guid $gpo.Id -Domain $SourceDomainName -Server $SourceDomainController `
                   -Path $BackupPath -ErrorAction Stop
        $backupCount++
    }
    catch {
        Write-Host ("[ERREUR] Echec de backup pour {0} : {1}" -f $gpo.DisplayName, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host "`n====================================================="
Write-Host "  RÉSUMÉ DE L'EXPORT DES GPO                          "
Write-Host "====================================================="
Write-Host ("Total GPO trouvées : {0}" -f $sourceGPOs.Count)
Write-Host ("Backups réalisés   : {0}" -f $backupCount)

Write-Host "`nFin de l'export GPO."