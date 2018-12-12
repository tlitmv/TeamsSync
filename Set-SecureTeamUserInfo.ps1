Write-Host "This will create a secure account object"
Write-Host "This needs to be run on the server that will perform the sync"
Read-Host -Prompt "Enter your userPrincipalName" | Out-File UPN.txt
Read-Host -Prompt "Enter your password" -AsSecureString | ConvertFrom-SecureString | Out-File cred.txt
