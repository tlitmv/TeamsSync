# Welcome to my script to automatically add/remove users from an Active Directory Group towards Microsoft Teams #
# Author: Antoon Bouw  #

# First let's check for prerequisites #

## 1: NuGet (needed for installing the Teams module)
$nuget = Get-PackageProvider -name nuget -force

if ($nuget.version -lt "2.8.5.201")
    {
        install-packageprovider -name nuget -minimumversion 2.8.5.201 -force -scope currentuser
    }
else
    {
        write-output "The right version of NuGet is installed"
    }

## 2: The Powershell Module for Teams
$TeamsModule = Get-Module -ListAvailable -Name MicrosoftTeams

if ($TeamsModule -eq $null)
{
    install-module microsoftteams -Scope CurrentUser -Force 
}
else
{
    write-output "Teams module is installed"
}

## 3: Active Directory Powershell Module

## This one is a prerequisite and should be installed at all time. Make sure you use the prereq.ps1 file to install all neccesary functions

$ADPowershell = get-windowsfeature -name rsat-ad-powershell

if ($ADPowershell.Installstate -eq "Installed")
{
    write-output "The AD Powershell cmdlets are installed."
}
else
{
    Write-Output "The Active Directory Powershell Module is not installed and cannot be installed automatically by this script."`n"Please Install Manually"
    exit 1
}

# Let's get going #
import-module activedirectory
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