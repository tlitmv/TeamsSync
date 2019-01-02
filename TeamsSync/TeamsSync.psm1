function Set-UsernameFile {
    param (
        [Parameter(Mandatory = $true)]
        [string] $File
    )
    $Script:UsernameFile = $File
}

function Set-PwdFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $File
    )
    $Script:PwdFile = $File
}

function Set-MapFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $File
    )
    $Script:MapFile = $File
}

function Assert-FilesSet {
    return (($null -ne $Script:UsernameFile) -and ($null -ne $Script:PwdFile) -and ($null -ne $Script:MapFile))
}

function Assert-Office365CredentialsExist {
    if (Assert-FilesSet) {
        if ((-not (Test-Path $Script:UsernameFile -PathType Leaf)) -or (-not (Test-Path $Script:PwdFile -PathType Leaf))) {
            Install-Office365Credentials
        }
        return $true;
    }
    else {
        return $false
    }
}

function Assert-TeamsModuleExists {
    if ($null -eq (Get-Module | Where-Object {$_.Name -eq "MicrosoftTeams"})) {
        Import-Module MicrosoftTeams
        if ($null -eq (Get-Module | Where-Object {$_.Name -eq "MicrosoftTeams"})) {
            Install-Module MicrosoftTeams -Scope AllUsers -Force -ErrorAction SilentlyContinue
            Import-Module MicrosoftTeams
            if ($null -eq (Get-Module | Where-Object {$_.Name -eq "MicrosoftTeams"})) {
                return $false
            }
            else {
                return $true
            }

        }
        else {
            return $true
        }
    }
    else {
        return $true
    }
}

function Assert-ActiveDirectoryModuleInstalled {
    if ($null -eq (Get-Module | Where-Object {$_.Name -eq "ActiveDirectory"})) {
        Import-Module ActiveDirectory
        if ($null -eq (Get-Module | Where-Object {$_.Name -eq "ActiveDirectory"})) {
            return Install-ActiveDirectoryModule
        }
    }
    else {
        return $true
    }
}

function Assert-Office365Connected {
    if ($null -eq $Script:Office365Session) {
        return $false
    }
    elseif (($Script:Office365Session.State -eq "Closed") -or ($Script.Office365Session.Availability -eq "None")) {
        return $false   
    }
    else {
        return $true
    }
}

function Assert-TeamsConnected {
    if ($null -eq $Script:TeamsConnected) {
        return $false
    }
    else {
        return $Script:TeamsConnected
    }
}

function Read-Office365Credentials {
    $Script:Username = Get-Content $Script:UsernameFile
    $Script:Password = Get-Content $Script:PwdFile | ConvertTo-SecureString
}

function Get-Office365Credentials {
    if (Assert-Office365CredentialsExist) {
        if ($null -eq $Script:Username -or $null -eq $Script:Password) {
            Read-Office365Credentials
        }
        return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Script:Username, $Script:Password
    }
    else {
        return $null
    }
}

function New-TeamFromOffice365Group {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Email
    )
    if (-not (Assert-TeamsModuleExists)) {
        Write-Host "Critical Error: Unable to install Microsoft Teams module."
    }
    if (-not (Assert-TeamsConnected)) {
        Import-TeamsSession
    }
    if (-not (Assert-Office365Connected)) {
        Import-Office365Session
    }
    $Group = Get-UnifiedGroup -Identity $Email
    $Guid = $Group.Name.Split("_")[1]
    New-Team -Group $Guid
}

function New-Office365Group {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Alias,
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $Email
    )
    if (-not (Assert-Office365Connected)) {
        Import-Office365Session
    }
    New-UnifiedGroup -AccessType Private -Alias $Alias -DisplayName $Name -Name $Name -PrimarySmtpAddress $Email -Owner $Script:Username -RequireSenderAuthenticationEnabled $true
    Set-UnifiedGroup -Identity $Name -HiddenFromAddressListsEnabled $false
}

function Install-Office365Credentials {
    Read-Host -Prompt "Enter your userPrincipalName" | Out-File $Script:UsernameFile
    Read-Host -Prompt "Enter your password" -AsSecureString | ConvertFrom-SecureString | Out-File $Script:PwdFile
}

function Install-ActiveDirectoryModule {
    #Current RSAT Download Links for W10
    $w10b1709x86 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x86.msu'
    $w10b1709x64 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x64.msu'

    $w10b1803x86 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1803-x86.msu'
    $w10b1803x64 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1803-x64.msu'

    $OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    $OSBuild = ([System.Environment]::OSVersion.Version).Build
    $Architecture = $env:PROCESSOR_ARCHITECTURE

    if ($OSCaption -like "*Windows Server*") {
        Import-Module ServerManager
        Install-WindowsFeature RSAT-AD-PowerShell

        # Install the help
        Update-Help -Module ActiveDirectory -Verbose -Force
        if ((Get-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell -ErrorAction SilentlyContinue).State -ne 'Enabled') {
            Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
        }
    }
    elseif ( $OSCaption -like "*Windows 10*") {
        switch ($OSBuild) {
            '16299' {
                switch ($Architecture) {
                    'x86' { $URL = $w10b1709x86 }
                    'AMD64' { $URL = $w10b1709x64 }
                }
            }
            '17134' { 
                switch ($Architecture) {
                    'x86' { $URL = $w10b1803x86 }
                    'AMD64' { $URL = $w10b1803x64 }
                }
            }
        }

        Write-Output "Now Downloading RSAT Tools installer"
        $Destination = $env:TEMP + "\" + $URL.Split('/')[-1]
        $LogFile = $env:TEMP + "\RSAT.log"
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($URL, $Destination)
        $WebClient.Dispose()
    
        Write-Output "Starting the Windows Update Service to install the RSAT Tools "
        Start-Process -FilePath wusa.exe -ArgumentList "$Destination /quiet /norestart /log:$LogFile" -Verbose -NoNewWindow
        do {
            Write-Host '.' -NoNewline
            Start-Sleep -Seconds 3
        } until (Get-HotFix -Id KB2693643 -ErrorAction SilentlyContinue)

        # Double-check that the role is enabled after install.

        # Install the help
        Update-Help -Module ActiveDirectory -Verbose -Force
        return ($null -ne (Get-Module | Where-Object {$_.Name -eq "ActiveDirectory"}))
    }
}

function Import-TeamsSession {
    $Credential = Get-Office365Credentials
    $TeamsSession = Connect-MicrosoftTeams -Credential $Credential
    if ($null -ne $TeamsSession) {
        $Script:TeamsConnected = $true
    }
    else {
        $Script:TeamsConnected = $false
    }
}

function Disconnect-TeamsSession {
    if ($Script:TeamsConnected) {
        Disconnect-MicrosoftTeams
        $Script:TeamsConnected = $false
    }
}

function Import-Office365Session {
    $Credential = Get-Office365Credentials
    $Script:Office365Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $Credential -Authentication Basic -AllowRedirection
    Import-PSSession $Script:Office365Session
}

function Get-Office365Session {
    return $Script:Office365Session
}

function Disconnect-Office365Session {
    Remove-PSSession -Session $Script:Office365Session
}

function Read-MapFile {
    if (Assert-FilesSet) {
        if (Test-Path $Script:MapFile -PathType Leaf) {
            $Script:MapContent = Import-Csv $Script:MapFile -Header ActiveDirectoryGroup, Team
            return $Script:MapContent;
        }
    }
}

function Update-Office365GroupEmailAddress {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Identity,
        [Parameter(Mandatory = $true)]
        [string] $NewEmail
    )
    if (Assert-Office365Connected) {
        Set-UnifiedGroup -Identity $Identity -PrimarySmtpAddress $NewEmail
    }
}

function Invoke-TeamsSyncUnload {
    Disconnect-Office365Session
    Disconnect-TeamsSession
}

function Invoke-TeamsSyncLoad {
    Set-DefaultFiles
    Import-Sessions
}

function Import-Sessions {
    Import-Office365Session
    Import-TeamsSession
}

function Set-DefaultFiles {
    Set-UsernameFile -File upn.txt
    Set-PwdFile -File pwd.txt
    Set-MapFile -File map.csv
}

function Invoke-TeamsSync {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $UserFile,
        [Parameter(Mandatory = $true)]
        [string]
        $PassFile,
        [Parameter(Mandatory = $true)]
        [string]
        $TeamsFile
    )

    Set-UsernameFile -File $UserFile
    Set-PwdFile -File $PassFile
    Set-MapFile -File $TeamsFile

    if (-not (Assert-TeamsModuleExists)) {
        Write-Host "Critical Error: Unable to install Microsoft Teams module."
        exit 1
    }

    if (-not (Assert-ActiveDirectoryModuleInstalled)) {
        Write-Host "Critical Error: Active Directory module missing."
        exit 1
    }

    $GroupMap = Read-MapFile
    if ($null -eq $GroupMap) {
        Write-Host "Critical Error: Error reading map file."
        exit 1
    }

    foreach ($Item in $GroupMap) {
        $ActiveDirectoryGroup = Get-ADGroup $Item.ActiveDirectoryGroup
        $ActiveDirectoryGroupMembers = $ActiveDirectoryGroup | Get-ADGroupMember | Get-ADUser | Select-Object UserPrincipalName
        $Team = Get-Team | Where-Object {$_.DisplayName -like $Item.Team}
        if ($null -eq $Teams) {
            Write-Host "Team: " $Item.Team " does not exist or account is not an owner."
        }
        else {
            
            $TeamMembers = Get-TeamUser -GroupId $Team.GroupId
            $ActiveDirectoryOnlyUsers = try {
                Compare-Object -DifferenceObject $ActiveDirectoryGroupMembers.UserPrincipalName -ReferenceObject $TeamMembers.User -IncludeEqual -ErrorAction SilentlyContinue | Where-Object {$_.SideIndicator -eq "=>"}
            }
            catch {
                Write-Host "No members in Active Directory group: " $ActiveDirectoryGroup.DisplayName "."
            }

            if (($null -ne $ActiveDirectoryOnlyUsers) -and ($ActiveDirectoryOnlyUsers.Count -ne 0)) {
                foreach ($ActiveDirectoryOnlyUser in $ActiveDirectoryOnlyUsers) {
                    Write-Host "Adding user: " $ActiveDirectoryOnlyUser.InputObject " to Team: " $Team.DisplayName
                    Add-TeamUser -GroupId $Team.GroupId -User $ActiveDirectoryOnlyUser.InputObject
                }
            }

            $TeamOnlyUsers = try {
                Compare-Object -DifferenceObject $ActiveDirectoryGroupMembers.UserPrincipalName -ReferenceObject $Team.User -IncludeEqual -ErrorAction SilentlyContinue | Where-Object {$_.SideIndicator -eq "<="}
            }
            catch {}

            if (($null -ne $TeamOnlyUsers) -and ($TeamOnlyUsers.Count -ne 0)) {
                foreach ($TeamOnlyUser in $TeamOnlyUsers) {
                    $TeamUserInfo = Get-TeamUser -GroupId $TeamInfo.groupid | Where-Object {$_.User -like $TeamOnlyUser.InputObject}
                    if($TeamUserInfo.Role -eq "Owner") {
                        Write-Host "Unable to remove owner: " $TeamOnlyUser.InputObject " from team: " $Item.Team "."
                        break
                    }
                    Write-Host "Removing User: " $TeamOnlyUser.InputObject " from Team: " $Team.DisplayName
                    Remove-TeamUser -GroupId $TeamInfo.groupid -User $TeamOnlyUser.InputObject
                }
            }
        }
    }

}