write-host "This will create a secure account object"
read-host -prompt "Enter your userprincipalname" | out-file UPN.txt
read-host -prompt "Enter your password"-assecurestring | convertfrom-securestring | out-file cred.txt
