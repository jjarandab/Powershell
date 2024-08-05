# Online Commands

## Unlock ALL locked accounts

``` powershell
Search-ADAccount -Lockedout | Unlock-AdAccount
```

## Force Sync Azure/O365

``` powershell
Start-ADSyncSyncCycle -PolicyType Delta
```

## Export Locked Accounts from OU

``` powershell
Search-ADAccount -SearchBase "OU=O365 Enabled,OU=Shaftesbury,DC=Shaftesbury,DC=local" -Lockedout | Export-Csv -NoTypeInformation -Path "C:\Locked_Export.csv"
```

## Export PWD/Lock State from OU

``` powershell
Get-ADUser -Filter * -SearchBase "OU=O365 Enabled,OU=Shaftesbury,DC=Shaftesbury,DC=local" -Properties Created, LastLogonDate, LastBadPasswordAttempt, passwordlastset, passwordneverexpires, PasswordExpired, LockedOut, AccountLockoutTime, BadLogonCount | Select-Object Enabled, Created, Name, UserPrincipalName, PasswordExpired, Passwordneverexpires, passwordlastset, LockedOut, AccountLockoutTime, BadLogonCount, LastBadPasswordAttempt, LastLogonDate | Export-Csv -Path "C:\USR_LOCK_Export.csv" -NoTypeInformation
```

## LastPasswordChange

Connect to M365

```powershell
Connect-MsolService
```

Get **LastPasswordChangeTimeStamp**

```powershell
Get-MsolUser -UserPrincipalName [nicolas@newcom.ca](<mailto:nicolas@newcom.ca>) | Select DisplayName,UserPrincipalName,LastPasswordChangeTimeStamp
```

Get all users who have changed password **more than 90 days** before

``` powershell
Get-MsolUser -All | Where {$_.LastPasswordChangeTimeStamp -lt ([System.DateTime]::Now).AddDays(-90)} | Sort-Object LastPasswordChangeTimeStamp -Descending | Select DisplayName,LastPasswordChangeTimeStamp
```

## Get-MobileDevice

``` powershell
Get-MobileDevice -ResultSize unlimited | Format-Table -Auto Identity,DeviceAccessState,IsManaged,IsCompliant,IsDisabled,DeviceOS
```

