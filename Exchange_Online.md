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
Connect-ExchangeOnline -UserPrincipalName <UPN>
```

Get mailbox info

``` powershell
Get-Mailbox -ResultSize Unlimited | Select-Object IsMailboxEnabled,AccountDisabled,DisplayName,UserPrincipalName,MailboxPlan,WhenCreated,WhenChanged | Export-CSV C:\”SHAFT.CSV” –NoTypeInformation -Encoding UTF8
```

