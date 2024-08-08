# AD User Handling

## Print AD user status and last modify date [PowerShell]

```powershell
Get-ADUser -Identity marias -Properties * | Select -Property Enabled,modifyTimeStamp
```

## Date Last Password Set

```powershell
Get-ADUser -Identity jason -properties PwdLastSet,PasswordLastSet  | sort Name | ft Name,PwdLastSet,PasswordLastSet
```

## Get last logon date

```powershell
Get-ADUser -Identity sparelaptop -Properties LastLogon | Select Name, @{Name=  'LastLogon';Expression={[DateTime]::FromFileTime($_.LastLogon)}}
```

## Hard Match

```powershell
#Print ObjectID 
Get-ADUser

-Identity james.g -Properties Name, ObjectGUID | Format-Table -Property Name, ObjectGUID -AutoSize  9a7ed32a-0ab4-4d46-aa48-2d7d273334f6  

#Print Base64 converted ObjectID  
Get-ADUser -Identity james.g -Properties Name, ObjectGUID | Format-Table -Property Name, ObjectGUID -AutoSize  [system.convert]::ToBase64String((Get-ADUser -Identity james.g).Objectguid.tobytearray())  
KtN+mrQKRk2qSC19JzM09g== 

# Install-Module
AzureAD  Connect-AzureAD  Set-AzureADUser -ObjectId "3adb2954-446d-497b-948b-b7d2a1da544d" -ImmutableId FU/dZaq8Q0Gawu+oayE0Cw==
```

## Password Never Expires

```powershell
get-aduser -filter * -properties Name, PasswordNeverExpires, WhenChanged | where { $_.passwordNeverExpires -eq "true" } | where {$_.enabled -eq "true"} | Format-Table -Property PasswordNeverExpires, Enabled,
WhenChanged, Name, UserPrincipalName -AutoSize24.150.167.57
```

## GET LAST LOGON

```powershell
Get-ADUser -Filter {SamAccountName -eq "username"} -Properties lastLogon | Select-Object Name, SamAccountName, @{Name="LastLogon"; Expression={[DateTime]::FromFileTime($_.lastLogon)}} | Export-CSV -Path "user_last_login.csv" -NoTypeInformation
```

## DISABLE PasswordNeverExpires

```powershell
Set-ADUser -Identity lwatson -PasswordNeverExpires:$FALSE
```
