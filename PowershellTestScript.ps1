$RootOU= "Vissers"
New-ADOrganizationalUnit -Name "$RootOU" -Path "DC=jenslabo, DC=com" -ProtectedFromAccidentalDeletion:$false -Server:"DC01.jenslabo.com"
New-ADGroup -Name "GUsers" -Path "OU=$RootOU,DC=jenslabo,DC=com" -GroupScope Global
$lines = Import-Csv -Path C:\PowershellTest\GebruikerslijstVissers.csv -Delimiter ";"
$lines | ForEach-Object { $_.Department } | Select-Object -Unique {
    New-ADOrganizationalUnit -Name $_ -Path "OU=$RootOU,DC=jenslabo,DC=com" -ProtectedFromAccidentalDeletion:$false -Server:"DC01.jenslabo.com"
    New-ADGroup -Name G$($_) -Path "OU=$($_),OU=$RootOU,DC=jenslabo,DC=com" -GroupScope Global
}
foreach ($user in $lines) {
    New-ADUser -Name $user.Name -Surname $user.Surname -SamAccountName $user.samaccountname `
        -GivenName $user.GivenName -Title $user.Title -Department $user.Department `
        -Company $user.company -UserPrincipalName $user.userPrincipalName -EmailAddress $user.Mail `
        -Path $user.Path -AccountPassword (ConvertTo-SecureString -AsPlainText "Admin123" -Force) -Enabled:$true
    Add-ADGroupMember G$($user.Department) $user.SamAccountName
    Add-ADGroupMember GUsers $user.SamAccountName
}