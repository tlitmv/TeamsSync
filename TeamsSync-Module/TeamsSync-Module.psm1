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

function Assert-Office365CredentialsExist {
    if (((Test-Path $Script:UsernameFile -PathType Leaf) -eq $false) -or ((Test-Path $Script:PwdFile -PathType Leaf) -eq $false)) {
        return $false
    }
    return $true;
}

function Read-Office365Credentials {
    $Script:Username = Get-Content $Script:UsernameFile
    $Script:Password = Get-Content $Script:PwdFile | ConvertTo-SecureString
}

function Get-Office365Credentials {
    if (Assert-CredentialsExist) {
        if ($null -eq $Script:Username -or $null -eq $Script:Password) {
            Read-Office365Credentials
        }
        return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Script:Username, $Script:Password
    }
    else {
        return $null
    }
}

function Assert-TeamModuleExists {
    if ($null = (Get-Module | Where-Object {$_.Name -eq "MicrosoftTeams"})) {
        Install-Module MicrosoftTeams -Scope AllUsers -Force
        $TeamsModule = Get-Module -ListAvailable -Name MicrosoftTeams
        if ($null -eq $TeamsModule) {
            # Failed to install Teams module.
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

function New-TeamFromOffice365Group {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Email
    )
    New-Team -Template $Email
}

function New-Office365Group {
    [Parameter(Mandatory = $true)]
    [string] $Alias,
    [Parameter(Mandatory = $true)]
    [string] $Name,
    [Parameter(Mandatory = $true)]
    [string] $Email
    if (-not (Assert-Office365Connected)) {
        Import-Office365Session
    }
    New-UnifiedGroup -AccessType Private -Alias $Alias -DisplayName $Name -Name $Name -PrimarySmtpAddress $Email -Owner $Script:Username -RequireSenderAuthenticationEnabled $true
}

function Install-Office365Credentials {
    Read-Host -Prompt "Enter your userPrincipalName" | Out-File $Script:UsernameFile
    Read-Host -Prompt "Enter your password" -AsSecureString | ConvertFrom-SecureString | Out-File $Script:PwdFile
}

function Assert-ActiveDirectoryModuleInstalled {
    if ((Get-WindowsFeature -Name RSAT-AD-PowerShel).Installstate -ne "Installed") {
        Install-ActiveDirectoryModule
        if (((Get-WindowsFeature -Name RSAT-AD-PowerShel).Installstate -ne "Installed")) {
            Install-Module ActiveDirectory
            return $true
        }
        else {
            return $false
        }
    }
    return $true
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
        if ((Get-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell -ErrorAction SilentlyContinue).State -ne 'Enabled') {
            Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
        }

        # Install the help
        Update-Help -Module ActiveDirectory -Verbose -Force
    }
}

function Assert-Office365Connected {
    Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    $result = $?
    return $result
}

function Import-Office365Session {
    $Credential = Get-Office365Credentials
    $Script:Office365Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $Credential -Authentication Basic -AllowRedirection -Name "Office365Session"
    Import-PSSession $Script:Office365Session
}

function Disconnect-Office365Session {
    Disconnect-PSSession -Session $Script:Office365Session
}