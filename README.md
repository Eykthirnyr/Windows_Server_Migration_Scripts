# Windows Server Migration Scripts

This repository contains PowerShell scripts that help automate common tasks when migrating from one Active Directory domain to another. The tools do not require any hard coded domain information and prompt for all necessary details when run.

## Scripts

### `GPO Backup Source.ps1`
Exports every Group Policy Object from a source domain to a local folder. Run this on the source domain controller or any machine with the GroupPolicy module installed.

### `GPO Backup Cible.ps1`
Imports backed‑up GPOs into a target domain. The script checks that the GroupPolicy Management Console (GPMC) is available and will attempt to install it if run on a Windows Server host.

### `Migration Tools.ps1`
Interactively copies selected Organizational Units, users and groups from a source domain to a target domain. It maintains group membership, updates each user to use the new domain suffix and produces a detailed summary log.

## Requirements
- Windows PowerShell with the ActiveDirectory and GroupPolicy modules
- Sufficient privileges in both the source and target domains

## Usage
1. Run **GPO Backup Source.ps1** on the source domain. Provide the domain controller name, domain name and a local backup path when prompted.
2. Copy the backup folder to the target environment.
3. Run **GPO Backup Cible.ps1** on the target domain. Supply the target domain information and the path to the backup folder.
4. (Optional) Run **Migration Tools.ps1** to migrate OUs, users and groups. The script guides you through the selection of OUs and handles user password creation and group membership replication.

All scripts output progress information to the console and do not store credentials or domain details in the files themselves.

## Notes
These scripts are provided as examples and should be reviewed and tested in a non‑production environment before use. They rely on standard PowerShell cmdlets and do not include any embedded credentials.
