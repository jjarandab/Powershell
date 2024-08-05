Remote Powershell

```` powershell
Enable-PSRemoting
$Cred = Get-Credential
Enter-PSSession -ComputerName DDCTOR2-190626 -Credential $Cred
````

