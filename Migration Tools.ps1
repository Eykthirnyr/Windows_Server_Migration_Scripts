#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Interactively copies selected OUs (and child OUs) from a source domain
    to a target domain, then copies all users and groups in those OUs,
    replicates group membership, sets user UPN to the new domain suffix,
    checks password complexity, and can prompt to overwrite existing users.

.DESCRIPTION
    1) Verifies AD module.
    2) Prompts for domain info.
    3) Re-prompts for password until basic complexity is met.
    4) Retrieves top-level OUs; user picks indices (example for multiple).
    5) Recursively replicates OUs, storing a source-to-target mapping.
    6) Copies users/groups in those OUs:
       - If user doesn't exist, create with new domain UPN suffix.
       - If user does exist, prompt to overwrite (including new UPN suffix).
    7) Copies group membership.
    8) Logs actions (Create, Skip, Overwrite, Error) and shows summary.
#>

################################################################################
# 1. CHECK DEPENDENCIES
################################################################################
Write-Host "Checking for Active Directory module..."
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ActiveDirectory module is not installed. Install RSAT/AD module, then re-run."
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

################################################################################
# 2. DEFINE GLOBALS & HELPER FUNCTIONS
################################################################################

# A global log array storing each action. Fields:
#   ObjectType (e.g. "OU","User","Group","MemberAdd")
#   Name
#   ParentOU
#   Action ("Create","Skip","Overwrite","Error")
#   ErrorMessage (if any)
$Global:MigrationLog = @()

Function Log-Action {
    param(
        [string]$ObjectType,
        [string]$Name,
        [string]$ParentOU,
        [string]$Action,         # "Create","Skip","Overwrite","Error"
        [string]$ErrorMessage
    )
    $entry = [PSCustomObject]@{
        ObjectType   = $ObjectType
        Name         = $Name
        ParentOU     = $ParentOU
        Action       = $Action
        ErrorMessage = $ErrorMessage
    }
    $Global:MigrationLog += $entry
}

Function Get-DomainDN {
    param([string]$DomainName)
    # "mydomain.local" -> "DC=mydomain,DC=local"
    return "DC=" + $DomainName -replace "\.",",DC="
}

# Simple function to check password complexity.
# Customize to match your domain policy as needed.
Function Test-PasswordComplexity {
    param([string]$PlainTextPassword)

    $minLength       = 8
    $hasUpper        = $PlainTextPassword -match '[A-Z]'
    $hasLower        = $PlainTextPassword -match '[a-z]'
    $hasDigit        = $PlainTextPassword -match '\d'
    $hasSpecial      = $PlainTextPassword -match '\W'  # non-word char
    $meetsMinLength  = ($PlainTextPassword.Length -ge $minLength)

    return ($hasUpper -and $hasLower -and $hasDigit -and $hasSpecial -and $meetsMinLength)
}

################################################################################
# 3. PROMPT FOR REQUIRED INFO (with password re-check)
################################################################################
Write-Host "===================================================="
Write-Host "Interactive OU, User, and Group Migration"
Write-Host "===================================================="

$SourceDC = Read-Host "Enter the Source Domain Controller (e.g. OldDC01.olddomain.local)"
$SourceDomainName = Read-Host "Enter the Source Domain Name (e.g. olddomain.local)"
$TargetDC = Read-Host "Enter the Target Domain Controller (e.g. NewDC01.newdomain.local)"
$TargetDomainName = Read-Host "Enter the Target Domain Name (e.g. newdomain.local)"

# Repeatedly prompt for password until complexity is met
do {
    $defaultPwdStr = Read-Host "Enter the default password for newly created user accounts"
    if (Test-PasswordComplexity $defaultPwdStr) {
        $validPassword = $true
    }
    else {
        Write-Host "`n[ERROR] Password does not meet complexity (>=8 chars, upper, lower, digit, special). Please try again." -ForegroundColor Red
        $validPassword = $false
    }
} while (-not $validPassword)

$DefaultUserPassword = ConvertTo-SecureString $defaultPwdStr -AsPlainText -Force

$forcePwdResetChoice = Read-Host "Do you want to force password reset at next logon? (y/n)"
$ForcePasswordReset = $false
if ($forcePwdResetChoice -eq 'y' -or $forcePwdResetChoice -eq 'Y') {
    $ForcePasswordReset = $true
}

Write-Host "`nRetrieving top-level OUs in $($SourceDomainName)..."

# Build domain root DN
$SourceRootDN = Get-DomainDN $SourceDomainName

# "Top-level" OUs = direct children of root
$topLevelOUs = Get-ADOrganizationalUnit -Server $SourceDC -SearchBase $SourceRootDN -SearchScope OneLevel -Filter * -ErrorAction Stop

Write-Host ""
Write-Host ("Top-Level OUs in {0}" -f $SourceDomainName)
$index = 0
foreach ($ou in $topLevelOUs) {
    Write-Host ("[{0}] {1}" -f $index, $ou.DistinguishedName)
    $index++
}
Write-Host ""
Write-Host "Example for multiple selection: '1,2'"
$selection = Read-Host "Enter the index(es) of the OU(s) you want to replicate"

# Parse input to integer array
$indexes = $selection -split "[,; ]+" | ForEach-Object { 
    $_ = $_.Trim()
    if ($_ -match "^\d+$") { [int]$_ }
}

# Build array of chosen OUs
$selectedOUs = @()
foreach ($i in $indexes) {
    if ($i -ge 0 -and $i -lt $topLevelOUs.Count) {
        $selectedOUs += $topLevelOUs[$i]
    }
}

if ($selectedOUs.Count -eq 0) {
    Write-Host "No valid OU selections. Exiting."
    return
}

Write-Host "You selected the following OU(s):"
$selectedOUs | ForEach-Object { Write-Host ("   {0}" -f $_.DistinguishedName) }

Write-Host ""
Write-Host "Press Enter to begin the migration..."
[void][System.Console]::ReadLine()

################################################################################
# 4. REPLICATE SELECTED OU SUBTREES (fixing null/collection issues)
################################################################################
$TargetRootDN = Get-DomainDN $TargetDomainName

# We'll store a mapping from SourceOU -> TargetOU
$OUMap = @{}

# Helper function that returns an ArrayList of all descendant OUs (including self)
function Get-OURecursive {
    param(
        [string]$Server,
        [string]$RootOUDN
    )

    $ouList = New-Object System.Collections.ArrayList

    # Direct child OUs
    $childOUs = Get-ADOrganizationalUnit -Server $Server `
                -SearchBase $RootOUDN -SearchScope OneLevel `
                -Filter * -ErrorAction SilentlyContinue

    if ($childOUs) {
        foreach ($c in $childOUs) {
            $ouList.Add($c) | Out-Null
            $grandChildren = Get-OURecursive -Server $Server -RootOUDN $c.DistinguishedName
            foreach ($gc in $grandChildren) {
                $ouList.Add($gc) | Out-Null
            }
        }
    }
    return $ouList
}

foreach ($selectedTopOU in $selectedOUs) {
    # Gather all child OUs for this subtree
    $allChildren = Get-OURecursive -Server $SourceDC -RootOUDN $selectedTopOU.DistinguishedName

    # Our full OU list includes the top-level OU itself + all children
    $ouList = New-Object System.Collections.ArrayList
    $ouList.Add($selectedTopOU) | Out-Null
    foreach ($child in $allChildren) {
        $ouList.Add($child) | Out-Null
    }

    # Sort by hierarchical depth so parent OUs are created before children
    $sortedOUList = $ouList | Sort-Object {
        $_.DistinguishedName.Split(',').Count
    }

    foreach ($ou in $sortedOUList) {
        $sourceOUDN = $ou.DistinguishedName

        # Remove domain portion from OU DN
        $domainRegex = ",(DC=.*)"
        $rdnNoDomain = $sourceOUDN -replace $domainRegex, ""

        $splitRDN = $rdnNoDomain -split ",", 2
        $thisOUNamePart = $splitRDN[0]
        $thisOUParent = $null
        if ($splitRDN.Count -ge 2) {
            $thisOUParent = $splitRDN[1]
        }

        $name = $thisOUNamePart -replace "^OU=",""

        if ([string]::IsNullOrWhiteSpace($thisOUParent)) {
            $targetParentDN = $TargetRootDN
        }
        else {
            $targetParentDN = "$thisOUParent,$TargetRootDN"
        }

        # Check if OU exists in target
        $existingTargetOU = Get-ADOrganizationalUnit -Server $TargetDC `
                            -SearchBase $targetParentDN `
                            -Filter "Name -eq '$name'" `
                            -ErrorAction SilentlyContinue

        if (-not $existingTargetOU) {
            Write-Host ("Creating OU: {0} under {1}" -f $name, $targetParentDN)
            try {
                New-ADOrganizationalUnit -Server $TargetDC -Name $name -Path $targetParentDN -ErrorAction Stop

                # Retrieve newly created OU
                $newOU = Get-ADOrganizationalUnit -Server $TargetDC -SearchBase $targetParentDN -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
                if ($newOU) {
                    Log-Action -ObjectType "OU" -Name $name -ParentOU $targetParentDN -Action "Create" -ErrorMessage ""
                    $OUMap[$sourceOUDN] = $newOU.DistinguishedName
                }
                else {
                    Log-Action -ObjectType "OU" -Name $name -ParentOU $targetParentDN -Action "Error" -ErrorMessage "Created but not found."
                    $OUMap[$sourceOUDN] = $null
                }
            }
            catch {
                Log-Action -ObjectType "OU" -Name $name -ParentOU $targetParentDN -Action "Error" -ErrorMessage $_.Exception.Message
                $OUMap[$sourceOUDN] = $null
            }
        }
        else {
            Write-Host ("OU already exists: {0} under {1}" -f $name, $targetParentDN)
            Log-Action -ObjectType "OU" -Name $name -ParentOU $targetParentDN -Action "Skip" -ErrorMessage "Already exists"
            $OUMap[$sourceOUDN] = $existingTargetOU.DistinguishedName
        }
    }
}

################################################################################
# 5. COPY USERS & GROUPS; PROMPT TO OVERWRITE IF ALREADY EXISTS
################################################################################
Write-Host ("`nCopying Users & Groups in selected OU subtrees for {0}..." -f $SourceDomainName)

# Which source OUs are validly mapped
$allSourceOUDNs = $OUMap.Keys | Where-Object { $OUMap[$_] -ne $null }

$allSourceUsers = @()
$allSourceGroups = @()

# For each mapped OU, gather users & groups recursively
foreach ($ouDN in $allSourceOUDNs) {
    $ouUsers = Get-ADUser -Server $SourceDC -SearchBase $ouDN -SearchScope Subtree -Filter * -Properties * -ErrorAction SilentlyContinue
    if ($ouUsers) { $allSourceUsers += $ouUsers }

    $ouGroups = Get-ADGroup -Server $SourceDC -SearchBase $ouDN -SearchScope Subtree -Filter * -Properties * -ErrorAction SilentlyContinue
    if ($ouGroups) { $allSourceGroups += $ouGroups }
}

# Remove duplicates if OU subtrees overlap
$allSourceUsers = $allSourceUsers | Select-Object -Unique
$allSourceGroups = $allSourceGroups | Select-Object -Unique

Write-Host ("Found {0} users and {1} groups in selected subtrees." -f $allSourceUsers.Count, $allSourceGroups.Count)

# --- Copy Users ---
foreach ($sourceUser in $allSourceUsers) {
    # Build the new UPN suffix for the target domain
    $newUPN = $sourceUser.SamAccountName + "@" + $TargetDomainName

    $sourceUserDN = $sourceUser.DistinguishedName
    $parentSplit  = $sourceUserDN -split ",",2
    if ($parentSplit.Count -lt 2) {
        $targetParentDN = "CN=Users,$TargetRootDN"
    }
    else {
        $sourceUserParentDN = $parentSplit[1]
        if ($OUMap.ContainsKey($sourceUserParentDN) -and $OUMap[$sourceUserParentDN]) {
            $targetParentDN = $OUMap[$sourceUserParentDN]
        }
        else {
            $targetParentDN = "CN=Users,$TargetRootDN"
        }
    }

    # Does user exist in target?
    $existingUser = Get-ADUser -Server $TargetDC -Filter {
        SamAccountName -eq $sourceUser.SamAccountName
    } -ErrorAction SilentlyContinue

    if (-not $existingUser) {
        # Create user in the new domain with the new UPN suffix
        Write-Host ("Creating user: {0}" -f $sourceUser.SamAccountName)
        try {
            New-ADUser -Server $TargetDC `
                       -Name $sourceUser.Name `
                       -SamAccountName $sourceUser.SamAccountName `
                       -UserPrincipalName $newUPN `  # <--- new domain suffix
                       -GivenName $sourceUser.GivenName `
                       -Surname $sourceUser.Surname `
                       -DisplayName $sourceUser.DisplayName `
                       -Path $targetParentDN `
                       -AccountPassword $DefaultUserPassword `
                       -Enabled $sourceUser.Enabled `
                       -ChangePasswordAtLogon $ForcePasswordReset

            Log-Action -ObjectType "User" -Name $sourceUser.SamAccountName -ParentOU $targetParentDN -Action "Create" -ErrorMessage ""
        }
        catch {
            Log-Action -ObjectType "User" -Name $sourceUser.SamAccountName -ParentOU $targetParentDN -Action "Error" -ErrorMessage $_.Exception.Message
        }
    }
    else {
        # Prompt whether to overwrite
        Write-Host ("User already exists: {0}" -f $sourceUser.SamAccountName)
        $choice = Read-Host "Overwrite this user? (y/n)"
        if ($choice -eq 'y' -or $choice -eq 'Y') {
            # Overwrite user attributes to match source, but with new domain suffix
            Write-Host ("Overwriting user: {0}" -f $sourceUser.SamAccountName)
            try {
                # If you want to re-set the password, do it here
                Set-ADAccountPassword -Server $TargetDC -Identity $existingUser.DistinguishedName -NewPassword $DefaultUserPassword -Reset -ErrorAction Stop

                if ($ForcePasswordReset) {
                    Set-ADUser -Server $TargetDC -Identity $existingUser.DistinguishedName -ChangePasswordAtLogon $true
                }

                # Replace various attributes
                Set-ADUser -Server $TargetDC -Identity $existingUser.DistinguishedName -Replace @{
                    displayName       = $sourceUser.DisplayName
                    givenName         = $sourceUser.GivenName
                    sn                = $sourceUser.Surname
                    # Force new domain suffix for UPN
                    userPrincipalName = $newUPN
                }

                # Optionally move them to the right OU
                Move-ADObject -Server $TargetDC -Identity $existingUser.DistinguishedName -TargetPath $targetParentDN -ErrorAction SilentlyContinue

                # Match the source's enable/disable state
                if ($sourceUser.Enabled -eq $false) {
                    Disable-ADAccount -Server $TargetDC -Identity $existingUser.DistinguishedName
                }
                else {
                    Enable-ADAccount -Server $TargetDC -Identity $existingUser.DistinguishedName
                }

                Log-Action -ObjectType "User" -Name $sourceUser.SamAccountName -ParentOU $targetParentDN -Action "Overwrite" -ErrorMessage ""
            }
            catch {
                Log-Action -ObjectType "User" -Name $sourceUser.SamAccountName -ParentOU $targetParentDN -Action "Error" -ErrorMessage $_.Exception.Message
            }
        }
        else {
            # Skip
            Log-Action -ObjectType "User" -Name $sourceUser.SamAccountName -ParentOU $existingUser.DistinguishedName -Action "Skip" -ErrorMessage "User chose skip"
        }
    }
}

# --- Copy Groups ---
foreach ($sourceGroup in $allSourceGroups) {
    $sourceGroupDN = $sourceGroup.DistinguishedName
    $parentSplit   = $sourceGroupDN -split ",",2
    if ($parentSplit.Count -lt 2) {
        $targetParentDN = "CN=Users,$TargetRootDN"
    }
    else {
        $sourceGroupParentDN = $parentSplit[1]
        if ($OUMap.ContainsKey($sourceGroupParentDN) -and $OUMap[$sourceGroupParentDN]) {
            $targetParentDN = $OUMap[$sourceGroupParentDN]
        }
        else {
            $targetParentDN = "CN=Users,$TargetRootDN"
        }
    }

    # Does group exist in target?
    $existingGroup = Get-ADGroup -Server $TargetDC -Filter {
        SamAccountName -eq $sourceGroup.SamAccountName
    } -ErrorAction SilentlyContinue

    if (-not $existingGroup) {
        Write-Host ("Creating group: {0}" -f $sourceGroup.SamAccountName)
        try {
            New-ADGroup -Server $TargetDC `
                        -Name $sourceGroup.Name `
                        -SamAccountName $sourceGroup.SamAccountName `
                        -GroupScope $sourceGroup.GroupScope `
                        -GroupCategory $sourceGroup.GroupCategory `
                        -Path $targetParentDN

            $newGroup = Get-ADGroup -Server $TargetDC -Filter { SamAccountName -eq $sourceGroup.SamAccountName } -ErrorAction SilentlyContinue
            if ($newGroup) {
                Log-Action -ObjectType "Group" -Name $sourceGroup.SamAccountName -ParentOU $targetParentDN -Action "Create" -ErrorMessage ""
            }
            else {
                Log-Action -ObjectType "Group" -Name $sourceGroup.SamAccountName -ParentOU $targetParentDN -Action "Error" -ErrorMessage "Group created but not found."
            }
        }
        catch {
            Log-Action -ObjectType "Group" -Name $sourceGroup.SamAccountName -ParentOU $targetParentDN -Action "Error" -ErrorMessage $_.Exception.Message
        }
    }
    else {
        # We'll just skip existing groups for now
        Write-Host ("Group already exists: {0}" -f $sourceGroup.SamAccountName)
        Log-Action -ObjectType "Group" -Name $sourceGroup.SamAccountName -ParentOU $existingGroup.DistinguishedName -Action "Skip" -ErrorMessage "Already exists"
    }
}

################################################################################
# 6. COPY GROUP MEMBERSHIPS
################################################################################
Write-Host ("`nCopying memberships for groups in {0}..." -f $SourceDomainName)

foreach ($sourceGroup in $allSourceGroups) {
    $members = Get-ADGroupMember -Server $SourceDC -Identity $sourceGroup.SamAccountName -ErrorAction SilentlyContinue
    if ($members) {
        # Find group in target
        $targetGroup = Get-ADGroup -Server $TargetDC -Filter {
            SamAccountName -eq $sourceGroup.SamAccountName
        } -ErrorAction SilentlyContinue

        if ($targetGroup) {
            foreach ($member in $members) {
                try {
                    # Look for user or group in target
                    $newDomainObject = Get-ADUser -Server $TargetDC -Filter {
                        SamAccountName -eq $member.SamAccountName
                    } -ErrorAction SilentlyContinue

                    if (-not $newDomainObject) {
                        $newDomainObject = Get-ADGroup -Server $TargetDC -Filter {
                            SamAccountName -eq $member.SamAccountName
                        } -ErrorAction SilentlyContinue
                    }

                    if ($newDomainObject) {
                        Write-Host ("  Adding '{0}' to group '{1}'" -f $newDomainObject.SamAccountName, $targetGroup.SamAccountName)
                        Add-ADGroupMember -Server $TargetDC -Identity $targetGroup.SamAccountName -Members $newDomainObject -ErrorAction SilentlyContinue
                        Log-Action -ObjectType "MemberAdd" -Name ("{0} -> {1}" -f $member.SamAccountName, $targetGroup.SamAccountName) -ParentOU $targetGroup.DistinguishedName -Action "Create" -ErrorMessage ""
                    }
                    else {
                        Log-Action -ObjectType "MemberAdd" -Name ("{0} -> {1}" -f $member.SamAccountName, $targetGroup.SamAccountName) -ParentOU $targetGroup.DistinguishedName -Action "Skip" -ErrorMessage "Member not found in target"
                    }
                }
                catch {
                    Log-Action -ObjectType "MemberAdd" -Name ("{0} -> {1}" -f $member.SamAccountName, $targetGroup.SamAccountName) -ParentOU $targetGroup.DistinguishedName -Action "Error" -ErrorMessage $_.Exception.Message
                }
            }
        }
    }
}

################################################################################
# 7. FINAL SUMMARY
################################################################################
Write-Host "`n===================================================="
Write-Host "            FINAL MIGRATION SUMMARY                  "
Write-Host "===================================================="

$ouCreated = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "OU" -and $_.Action -eq "Create" }
$ouSkipped = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "OU" -and $_.Action -eq "Skip" }
$ouErrors  = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "OU" -and $_.Action -eq "Error" }

$userCreated   = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "User" -and $_.Action -eq "Create" }
$userSkipped   = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "User" -and $_.Action -eq "Skip" }
$userOverwrote = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "User" -and $_.Action -eq "Overwrite" }
$userErrors    = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "User" -and $_.Action -eq "Error" }

$groupCreated = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "Group" -and $_.Action -eq "Create" }
$groupSkipped = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "Group" -and $_.Action -eq "Skip" }
$groupErrors  = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "Group" -and $_.Action -eq "Error" }

$membersCreated = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "MemberAdd" -and $_.Action -eq "Create" }
$membersSkipped = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "MemberAdd" -and $_.Action -eq "Skip" }
$membersErrors  = $Global:MigrationLog | Where-Object { $_.ObjectType -eq "MemberAdd" -and $_.Action -eq "Error" }

Write-Host ("OUs created:       {0}" -f $ouCreated.Count)
Write-Host ("OUs skipped:       {0}" -f $ouSkipped.Count)
Write-Host ("OUs errors:        {0}" -f $ouErrors.Count)
Write-Host ("Users created:     {0}" -f $userCreated.Count)
Write-Host ("Users overwritten: {0}" -f $userOverwrote.Count)
Write-Host ("Users skipped:     {0}" -f $userSkipped.Count)
Write-Host ("Users errors:      {0}" -f $userErrors.Count)
Write-Host ("Groups created:    {0}" -f $groupCreated.Count)
Write-Host ("Groups skipped:    {0}" -f $groupSkipped.Count)
Write-Host ("Groups errors:     {0}" -f $groupErrors.Count)
Write-Host ("Member additions:  {0}" -f $membersCreated.Count)
Write-Host ("Member skipped:    {0}" -f $membersSkipped.Count)
Write-Host ("Member errors:     {0}" -f $membersErrors.Count)

Write-Host "`nAny objects with 'Error' or 'Skip' or 'Overwrite' are listed below:"
Write-Host "----------------------------------------------------"

$problemObjects = $Global:MigrationLog | Where-Object { $_.Action -in @("Skip","Error","Overwrite") }
if ($problemObjects.Count -eq 0) {
    Write-Host "No problems or special actions detected. Everything created successfully!"
} else {
    $problemObjects | Sort-Object ObjectType,Name | Format-Table ObjectType, Name, ParentOU, Action, ErrorMessage -AutoSize
}

Write-Host "`nDone."
Write-Host "===================================================="
