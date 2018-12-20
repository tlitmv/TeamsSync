Param (	
    [Parameter(Mandatory = $True)]
    [string] $Alias,
    [Parameter(Mandatory = $True)]
    [string] $Name,
    [Parameter(Mandatory = $True)]
    [string] $Email,
    [Parameter(Mandatory = $True)]
    [string] $Owner
)
New-UnifiedGroup -AccessType Private -Alias $Alias -DisplayName $Name -Name $Name -PrimarySmtpAddress $Email -Owner "admin@seabreezemgmt.com" -RequireSenderAuthenticationEnabled $true