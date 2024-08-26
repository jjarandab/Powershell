# Online Commands

## Unlock ALL locked accounts

```powershell
Search-ADAccount -Lockedout | Unlock-AdAccount
```

## Force Sync Azure/O365

```powershell
Start-ADSyncSyncCycle -PolicyType Delta
```

## Export Locked Accounts from OU

```powershell
Search-ADAccount -SearchBase "OU=O365 Enabled,OU=Shaftesbury,DC=Shaftesbury,DC=local" -Lockedout | Export-Csv -NoTypeInformation -Path "C:\Locked_Export.csv"
```

## Export PWD/Lock State from OU

```powershell
Get-ADUser -Filter * -SearchBase "OU=O365 Enabled,OU=Shaftesbury,DC=Shaftesbury,DC=local" -Properties Created, LastLogonDate, LastBadPasswordAttempt, passwordlastset, passwordneverexpires, PasswordExpired, LockedOut, AccountLockoutTime, BadLogonCount | Select-Object Enabled, Created, Name, UserPrincipalName, PasswordExpired, Passwordneverexpires, passwordlastset, LockedOut, AccountLockoutTime, BadLogonCount, LastBadPasswordAttempt, LastLogonDate | Export-Csv -Path "C:\USR_LOCK_Export.csv" -NoTypeInformation
```

## LastPasswordChange

Connect to M365

```powershell
#Connect
Connect-MsolService
#Get LastPasswordChangeTimeStamp
Get-MsolUser -UserPrincipalName [nicolas@newcom.ca](<mailto:nicolas@newcom.ca>) | Select DisplayName,UserPrincipalName,LastPasswordChangeTimeStamp
#Get all users who have changed password **more than 90 days** before
Get-MsolUser -All | Where {$_.LastPasswordChangeTimeStamp -lt ([System.DateTime]::Now).AddDays(-90)} | Sort-Object LastPasswordChangeTimeStamp -Descending | Select DisplayName,LastPasswordChangeTimeStamp
```

## Get-MobileDevice

```powershell
Get-MobileDevice -ResultSize unlimited | Format-Table -Auto Identity,DeviceAccessState,IsManaged,IsCompliant,IsDisabled,DeviceOS
```

## Get SSID via CMD

This will show the profiles the current profile is the connection

```powershell
netsh wlan show profiles
```

Other example: SSID is the current connected wifi.

```powershell
netsh WLAN show interfaces
```

# Get Devices

```powershell
Get-PnpDevice -PresentOnly
```

# Program Handling

Find Program

```powershell
Get-WmiObject -Class
Win32_Product | Select-Object -Property Name

Get-WmiObject -Class
Win32_Product | Where-Object{$_.Name -eq "MiShareApp"}
```

Uninstall

```powershell
$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "MiCollab"}
$MyApp.Uninstall()
```

```powershell
Get-Process MiCollab  -IncludeUserName
```

## Hard Match

[How to Hard Match a User in Office 365 - Easy365Manager](https://www.easy365manager.com/how-to-hard-match-a-user-in-office-365/)

```powershell
#Print ObjectID
Get-ADUser -Identity james.g -Properties Name, ObjectGUID | Format-Table -Property Name, ObjectGUID -AutoSize 9a7ed32a-0ab4-4d46-aa48-2d7d273334
f6
#Print Bas64 Converted ObjectID
Get-ADUser -Identity james.g -Properties Name, ObjectGUID | Format-Table -Property Name, ObjectGUID -AutoSize [system.convert]::ToBase64String((Get-ADUser -Identity james.g).Objectguid.tobytearray()) KtN+mrQKRk2qSC19JzM09g==

# Install AzureAD Module
Install-Module AzureAD
Connect-AzureAD
Set-AzureADUser -ObjectId "3adb2954-446d-497b-948b-b7d2a1da544d" -ImmutableId FU/dZaq8Q0Gawu+oayE0Cw==
```

## Intune Device Enrolment

```
# Intune Device Enrollement
Requirements:
-Windows 10 1706 and later
-device must be registered in Azure AD
-Microsoft Intune LIcenses
Microsoft 365 E5
Microsoft 365 E3
Enterprise Mobility + Security E5
Enterprise Mobility + Security E3
Microsoft 365 Business Premium
Microsoft 365 F1
Microsoft 365 F3
Microsoft 365 Government G5
Microsoft 365 Government G3
Intune for Education

1.Ensure that the Autoenrollment is activated in the Intune Portal
Microsoft Endpoint>Devices>Enroll devices>Automatic enrollment>MDM user scope = All

2.Create OU/Security Group

3.Create GPO
Computer Configuration > Policies > Administrative Templates > Windows Components > MDM > Edit the Enable Automatic MDM enrollment using default Azure AD Credentials = Enable
Select Credentials type to use = User Credentials

gpupdate/force
```
