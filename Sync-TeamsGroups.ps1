Import-Module .\TeamsSync-Module

Param (
    [Parameter(Mandatory = $True)]
    [ValidateSet('AddToActiveDirectory', 'RemoveFromTeam')]
    [string] $MissingFromActiveDirctory
)

# Set module variables
Set-UpnFile -File ".\upn.txt"
Set-PwdFile -File ".\pwd.txt"

# See if credentials have been created.
if (-not (Assert-Office365CredentialsExist -UPNFile $UPNFile -PwdFile $PwdFile)) {
    Install-Office365Credentials
}

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

# Make sure Microsoft Teams module is installed
if (-not (Assert-TeamModuleExists)) {
    Write-Host "Critical Error: Unable to install Microsoft Teams module"
    exit 1
}

# Make sure Microsoft Active Directory module is installed
if (-not (Assert-ActiveDirectoryModuleInstalled)) {
    Write-Host "Critical Error: Unable to install Active Directory module"
    exit 1
}

# Let's get going #
Connect-MicrosoftTeams -Credential (Get-Office365Credentials)

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