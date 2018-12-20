# Welcome to my script to automatically add/remove users from an Active Directory Group towards Microsoft Teams #
# Author: Antoon Bouw  #

# First let's check for prerequisites #
Param (
    [Parameter(Mandatory = $True)]
    [ValidateSet('AddToActiveDirectory', 'RemoveFromTeam')]
    [string] $MissingFromActiveDirctory
)

# See if credentials have been created.
if (((Test-Path .\upn.txt -PathType Leaf) -eq $false) -or ((Test-Path .\cred.txt -PathType Leaf) -eq $false)) {
    Write-Host ""
    Write-Host "Error: Please run Set-SecureTeamUserInfo.ps1 before running this script."
    Write-Host ""
    exit 1
}

$Username = Get-Content UPN.txt
$Password = Get-Content cred.txt | ConvertTo-SecureString

## 1: NuGet (needed for installing the Teams module)
$NuGetProvider = Get-PackageProvider -Name NuGet -Force
if ($NuGetProvider.version -lt "2.8.5.201") {
    Write-Output "Installing NuGet..."
    Install-PackageProvider -Name NuGet -Scope AllUsers -Force
    $NuGetProvider = Get-PackageProvider -Name NuGet -Force
    if ($null -eq $NuGetProvider) {
        # Failed to install NuGet.
        exit 1
    }
    Write-Output "Finished installing NuGet."
    Write-Output "NuGet Version: " + $NuGetModule.version
}

## 2: The Powershell Module for Teams
$TeamsModule = Get-Module -ListAvailable -Name MicrosoftTeams
if ($null -eq $TeamsModule) {
    Install-Module MicrosoftTeams -Scope AllUsers -Force
    $TeamsModule = Get-Module -ListAvailable -Name MicrosoftTeams
    if ($null -eq $TeamsModule) {
        # Failed to install Teams module.
        exit 1
    }
}

## 3: Active Directory Powershell Module
$ADPowershell = Get-WindowsFeature -Name rsat-ad-powershell
if ($ADPowershell.Installstate -ne "Installed") {
    Write-Output "The Active Directory Powershell Module is not installed and cannot be installed automatically by this script."
    Write-Output "Please run Install-ActiveDirectoryModule.ps1 as administrator"
    exit 1
}

# Let's get going #
Import-Module ActiveDirectory
$ADGroupToTeamMap = Import-Csv Teams.csv -Header AD_Group, MS_Team
$Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password
Connect-MicrosoftTeams -Credential $Credentials

foreach ($Item in $ADGroupToTeamMap) {
    # Get Active Directory group and members.
    $ADGroup = Get-ADGroup $Item.AD_Group
    $ADGroupMembers = $ADGroup | Get-ADGroupMember | Get-ADUser | Select-Object UserPrincipalName
    Write-Host $ADGroup
    Write-Host $ADGroupMembers

    # Check to see if Active Directory group maps to a Team.
    $Team = Get-Team | Where-Object {$_.DisplayName -like $Item.MS_Team}
    if ($null -eq $Team) {
        Write-Host "Team: " $Item.MS_Team " does not exist or Service Account is not owner"
        break	
    }
    else {
        # Get Team users
        $TeamUsers = Get-TeamUser -GroupId $Team.GroupId

        # Gather a list of Active Directory users that do not belong to the Team
        $ADOnlyUsers = try {
            Compare-Object -DifferenceObject $ADGroupMembers.UserPrincipalName -ReferenceObject $TeamUsers.User -IncludeEqual -ErrorAction SilentlyContinue | Where-Object {$_.SideIndicator -eq "=>"}
        }
        catch { Write-Host "Please add members to group " $ADGroup.Name ". Please make sure the owner is one of them." }

        # Add missing Active Directory users to Team
        foreach ($ADOnlyUser in $ADOnlyUsers) {
            Write-Host "Adding User " $ADOnlyUser.InputObject " to Team " $Team.DisplayName
            Add-TeamUser -GroupId $Team.GroupId -User $ADOnlyUser.InputObject
        }

        # Gather a list of Team users that do not belong to the Active Directory group
        $TeamOnlyUsers = try {
            Compare-Object -DifferenceObject $ADGroup.UserPrincipalName -ReferenceObject $Team.User -IncludeEqual -ErrorAction SilentlyContinue | Where-Object {$_.SideIndicator -eq "<="}
        }
        catch {}

        # Remove Team users that do not belong to the Active Directory group
        if ($MissingFromActiveDirctory -eq "RemoveFromTeam") {
            foreach ($TeamOnlyUser in $TeamOnlyUsers) {
                Write-Host "Removing User " $TeamOnlyUser.InputObject " from Team " $Team.DisplayName
                $TeamUserInfo = Get-TeamUser -GroupId $TeamInfo.groupid | Where-Object {$_.User -like $TeamOnlyUser.InputObject}
                if ($TeamUserInfo.Role -eq "Owner") { break }
                Remove-TeamUser -GroupId $TeamInfo.groupid -User $TeamOnlyUser.InputObject
            }
        }
        elseif ($MissingFromActiveDirctory -eq "AddToActiveDirectory") {
            foreach ($TeamOnlyUser in $TeamOnlyUsers) {
                Write-Host "Adding User " $TeamOnlyUser.InputObject " to Active Directory group " $True
            }
        }
    }
}