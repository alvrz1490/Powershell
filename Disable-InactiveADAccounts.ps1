<#
.SYNOPSIS
    Disables AD accounts inactive for more than 90 days, moves them to a Disabled OU, 
    updates descriptions, and logs activity for RMF AU-2 compliance.

.DESCRIPTION
    This script checks for enabled users who haven't logged on in X days.
    It excludes specified accounts, disables the user, moves them to a target OU,
    appends a note to the description, and exports a CSV report.

.NOTES
    Make sure the RSAT Active Directory module is installed.
    Run as Administrator.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [int]$DaysInactive = 90,
    [string]$TargetDisabledOU = "OU=Disabled Users,DC=corp,DC=example,DC=com",
    [string]$LogPath = "C:\Admin\Logs\InactiveUsers",
    [string[]]$ExclusionList = @("Administrator", "krbtgt", "Guest", "ServiceAccount1")
)

# --- Setup ---
Import-Module ActiveDirectory
$DateThreshold = (Get-Date).AddDays(-$DaysInactive)
$Report = @()
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$CsvFile = "$LogPath\Disabled_Users_Report_$Timestamp.csv"

# Ensure Log Directory Exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
}

# --- Main Logic ---
Write-Verbose "Finding users inactive since $DateThreshold..."

# Validate Target OU exists before starting
try {
    Get-ADOrganizationalUnit -Identity $TargetDisabledOU -ErrorAction Stop | Out-Null
} catch {
    Write-Error "CRITICAL: The Target OU '$TargetDisabledOU' was not found. Script aborted."
    exit
}

# Get all enabled users with necessary properties
$Users = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate, Description, WhenCreated

foreach ($User in $Users) {
    
    # 1. Check Exclusion List
    if ($ExclusionList -contains $User.SamAccountName) {
        Write-Verbose "Skipping excluded account: $($User.SamAccountName)"
        continue
    }

    # 2. Determine Inactivity
    # Note: If LastLogonDate is null, check if the account was created > 90 days ago (Never logged on)
    $IsInactive = $false
    
    if ($User.LastLogonDate) {
        if ($User.LastLogonDate -lt $DateThreshold) {
            $IsInactive = $true
        }
    } elseif ($User.WhenCreated -lt $DateThreshold) {
        # Account created over 90 days ago but never logged into
        $IsInactive = $true
        Write-Verbose "Account $($User.SamAccountName) has never logged on and is older than 90 days."
    }

    # 3. Process Inactive User
    if ($IsInactive) {
        Write-Host "Processing $($User.SamAccountName)..." -ForegroundColor Yellow
        
        try {
            # Define the new description (Appends to existing)
            $NewDesc = "$($User.Description) [Disabled on $(Get-Date -Format 'yyyy-MM-dd') due to inactivity by Angel A. Alvarez (Employee #12345)]"

            # Action: Disable, Update Description, Move
            # -WhatIf is handled automatically by CmdletBinding, but we wrap the logic block
            if ($PSCmdlet.ShouldProcess($User.SamAccountName, "Disable, Update Description, Move")) {
                
                Set-ADUser -Identity $User -Enabled $false -Description $NewDesc -ErrorAction Stop
                Move-ADObject -Identity $User -TargetPath $TargetDisabledOU -ErrorAction Stop
                
                Write-Host "Successfully disabled $($User.SamAccountName)" -ForegroundColor Green

                # Add to Report
                $Report += [PSCustomObject]@{
                    SamAccountName = $User.SamAccountName
                    DisplayName    = $User.Name
                    LastLogon      = if ($User.LastLogonDate) { $User.LastLogonDate } else { "Never" }
                    DateDisabled   = Get-Date
                    Action         = "Disabled & Moved"
                }
            }
        }
        catch {
            Write-Error "Failed to process $($User.SamAccountName): $_"
        }
    }
}

# --- Export Report ---
if ($Report.Count -gt 0) {
    $Report | Export-Csv -Path $CsvFile -NoTypeInformation
    Write-Host "Report generated at $CsvFile" -ForegroundColor Cyan
} else {
    Write-Host "No inactive accounts found." -ForegroundColor Cyan
}