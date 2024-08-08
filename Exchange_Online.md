# Exchange Online

``` powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force;
Install-PackageProvider -Name NuGet -Force;
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted;
Install-Module -Name ExchangeOnlineManagement -Force;
Import-Module ExchangeOnlineManagement;
Connect-ExchangeOnline;
```

Install requirement

```powershell
Install-Module -Name ExchangeOnlineManagement -RequiredVersion 1.0.1
Install-Module MSOnline -Force
```

Import Module

```powershell
Import-Module ExchangeOnlineManagement
```

Connect to Exchange with admin creds

```powershell
Connect-ExchangeOnline
#or
Connect-ExchangeOnline -UserPrincipalName <UPN>
```

Get mailbox info

``` powershell
Get-Mailbox -ResultSize Unlimited | Select-Object IsMailboxEnabled,AccountDisabled,DisplayName,UserPrincipalName,MailboxPlan,WhenCreated,WhenChanged | Export-CSV C:\”SHAFT.CSV” –NoTypeInformation -Encoding UTF8
```

Microsoft Online [Password Never Expires]

``` powershell
Install-Module MSOnline
Connect-MsolService
cd C:\Users\username\Documents\Scripts
.\GetMFAStatus.ps1 | Export-CSV c:\PasswordNeverExpires.csv -noTypeInformation
#or
Get-MsolUser -All | Where-Object {$_.PasswordNeverExpires -eq $true -and $_.IsLicensed -eq $true}| Select UserPrincipalName, DisplayName, LastPasswordChangeTimestamp,PasswordNeverExpires,LastDirSyncTime,BlockCredential,StrongPasswordRequired,WhenCreated,@{N="LastLogonDate";E={(Get-MailboxStatistics $_.UserPrincipalName).LastLogonTime}},@{n="Licenses Type";e={$_.Licenses.AccountSKUid}} | Export-Csv C:\PasswordNeverExpires.csv
#or
Get-MsolUser | Where-Object {$_.PasswordNeverExpires -eq $true -and $_.IsLicensed -eq $true} | Select-Object DisplayName,UserPrincipalName,LastPasswordChangeTimestamp,Licenses,PasswordNeverExpires,DirSyncEnabled,BlockCredential,StrongPasswordRequired,WhenCreated | Export-Csv C:\LicensedUsers.csv
```

Change Password on nextlogin

``` powershell
Set-MsolUserPassword -UserPrincipalName skybartas@shaftesbury.ca -ForceChangePasswordOnly $true -ForceChangePassword $true
```

