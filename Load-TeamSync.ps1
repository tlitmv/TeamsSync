Import-Module .\TeamsSync-Module

Set-UsernameFile -File ".\upn.txt"
Set-PwdFile -File ".\pwd.txt"
Set-MapFile -File ".\teams.csv"