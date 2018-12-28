# $Groups = Import-Csv -Path groups.csv -Header Alias, Name, Email
$Groups = Import-Csv -Path groups.csv -Header Alias, Name
foreach ($Group in $Groups) {
    try {
        New-Office365Group -Alias $Group.Alias -Name $Group.Name -Email $Group.Alias"@seabreezemgmt.com"
    }
    catch {
        $_ | Out-File errors.txt -Append
    }
}
