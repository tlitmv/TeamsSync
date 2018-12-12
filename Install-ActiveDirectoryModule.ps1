#requires -RunAsAdministrator

#Current RSAT Download Links for W10
$w10b1709x86 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x86.msu'
$w10b1709x64 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x64.msu'

$w10b1803x86 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1803-x86.msu'
$w10b1803x64 = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1803-x64.msu'

$OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
$OSBuild = ([System.Environment]::OSVersion.Version).Build
$Architecture = $env:PROCESSOR_ARCHITECTURE

if($OSCaption -like "*Windows Server*") {
    Import-Module ServerManager
    Install-WindowsFeature RSAT-AD-PowerShell

    # Install the help
    Update-Help -Module ActiveDirectory -Verbose -Force
}
elseif ( $OSCaption -like "*Windows 10*") {
    switch($OSBuild) {
        '16299' {
            switch($Architecture) {
                'x86' { $URL = $w10b1709x86 }
                'AMD64' { $URL = $w10b1709x64 }
            }
        }
        '17134' { 
            switch($Architecture) {
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
# Optionally verify the install.
#dir (Join-Path -Path $HOME -ChildPath Downloads\*msu)
#Get-HotFix -Id KB2693643
#Get-Help Get-ADDomain
#Get-ADDomain