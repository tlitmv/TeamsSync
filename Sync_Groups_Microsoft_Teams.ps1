# Welcome to my script to automatically add/remove users from an Active Directory Group towards Microsoft Teams #
# Author: Antoon Bouw  #

# First let's check for prerequisites #
function Confirm-Module ($Module) {
    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $Module}) {
    } else {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module}) {
            Import-Module $Module -Verbose
        } else {
            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $Module | Where-Object {$_.Name -eq $Module}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
            } else {
                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}

## 1: NuGet (needed for installing the Teams module)
$NuGetProvider = Get-PackageProvider -Name NuGet -Force

if ($NuGetProvider.version -lt "2.8.5.201") {
	Write-Output "Installing NuGet..."
	Install-PackageProvider -Name NuGet -Scope AllUsers -Force
	$NuGetProvider = Get-PackageProvider -Name NuGet -Force
	Write-Output "Finished installing NuGet."
	Write-Output "NuGet Version: " + $NuGetModule.version
}

## 2: The Powershell Module for Teams
$TeamsModule = Get-Module -ListAvailable -Name MicrosoftTeams

if ($null -eq $TeamsModule) {
    Install-Module MicrosoftTeams -Scope AllUsers -Force 
}

## 3: Active Directory Powershell Module

## This one is a prerequisite and should be installed at all time. Make sure you use the prereq.ps1 file to install all neccesary functions

$ADPowershell = Get-WindowsFeature -Name rsat-ad-powershell

if ($ADPowershell.Installstate -ne "Installed") {
    Write-Output "The Active Directory Powershell Module is not installed and cannot be installed automatically by this script."`n"Please Install Manually"
    exit 1
}

# Let's get going #
Import-Module ActiveDirectory
$teams = import-csv Teams.csv -Header AD_Group,MS_Team
$username = get-content UPN.txt
$password = get-content cred.txt | convertto-securestring
$credentials = new-object -typename System.Management.Automation.PSCredential -argumentlist $username,$password
connect-microsoftteams -credential $credentials

Foreach ($team in $teams)
{
    $groupuserinfo = get-adgroup $team.AD_Group | get-adgroupmember | get-aduser | select-object UserPrincipalName
    $teaminfo = get-team | where-object {$_.DisplayName -like $team.MS_Team}
    if ($teaminfo -eq $null)
	{
		write-host "Team"$team.MS_Team"does not exist or Service Account is not owner"
		break	
	}
    Else
	{
	    $teamuserinfo = get-teamuser -groupid $teaminfo.groupid
	    $directoryonlyusers = try { compare-object -differenceobject $groupuserinfo.userprincipalname -referenceobject $teamuserinfo.user -includeequal -erroraction silentlycontinue | where-object {$_.SideIndicator -eq "=>"}} catch { write-host "Please add members to group"$team.AD_Group"Please make sure the owner is one of them!!!!" }
	    foreach ($directoryonlyuser in $directoryonlyusers)
		{
			write-host "Adding User"$directoryonlyuser.InputObject"to Team"$teaminfo.displayname
			add-teamuser -groupid $teaminfo.groupid -user $directoryonlyuser.inputobject
		}
	    $teamonlyusers = try { compare-object -differenceobject $groupuserinfo.userprincipalname -referenceobject $teamuserinfo.user -includeequal -erroraction silentlycontinue | where-object {$_.SideIndicator -eq "<="}} catch {}
	    foreach ($teamonlyuser in $teamonlyusers)		
		{
			write-host "Removing User"$teamonlyuser.InputObject"from Team"$teaminfo.displayname
			$teamuserinfo = Get-TeamUser -GroupId $teaminfo.groupid | Where-Object {$_.User -like $teamonlyuser.inputobject}
			if ($teamuserinfo.role -eq "Owner")
				{
					write-host "User"$teamonlyuser.InputObject"is not available in AD group, but cannot be removed from"$teaminfo.displayname"because it's an owner."
					break
				}
			remove-teamuser -groupid $teaminfo.groupid -user $teamonlyuser.inputobject
		}
	}
}