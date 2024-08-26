# Exchange Online

```powershell
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

```powershell
Get-Mailbox -ResultSize Unlimited | Select-Object IsMailboxEnabled,AccountDisabled,DisplayName,UserPrincipalName,MailboxPlan,WhenCreated,WhenChanged | Export-CSV C:\”SHAFT.CSV” –NoTypeInformation -Encoding UTF8
```

Microsoft Online [Password Never Expires]

```powershell
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

```powershell
Set-MsolUserPassword -UserPrincipalName skybartas@shaftesbury.ca -ForceChangePasswordOnly $true -ForceChangePassword $true
```

Exchange PST Export

| EAC > Roles > AdminRoles > Discovery Management > Add Admin account and Export role                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| compliance.microsoft.com > Roles and Scopes > Permissions > eDiscovery Manager > Edit > Manage eDiscovery Administrator > Chose User compliance.microsoft.com > eDiscovery > Standard > Create |

Microsoft Exchange [Bulk Add Senders to Existing Rule 1024 Limit]

```powershell
$senders = Import-Csv -Path "B:\senders.csv"
$totalSenders = $senders.Count
$currentIndex = 0

foreach ($sender in $senders) {
    $currentIndex++
    Write-Host "Processing $($sender.Sender) ($currentIndex of $totalSenders)..."
    
    $currentRule = Get-TransportRule -Identity "Whitelist Multiple Senders 1"
    $currentRule.From += $sender.EmailAddress
    Set-TransportRule -Identity "Whitelist Multiple Senders 1" -From $currentRule.From
    
    Write-Host "Added $($sender.Sender) to the rule. ($currentIndex of $totalSenders added)"
}

Write-Host "All senders processed. Rule update complete."
```

Microsoft Exchange [Bulk Add Domains to Existing Rule 1024 Limit]

```powershell
$domains = Import-Csv -Path "B:\domains.csv"
$totalDomains = $domains.Count
$currentIndex = 0

foreach ($domain in $domains) {
    $currentIndex++
    Write-Host "Processing $($domain.Domain) ($currentIndex of $totalDomains)..."
    
    $currentRule = Get-TransportRule -Identity "Whitelist Multiple Domains"
    if ($currentRule.SenderDomainIs -notcontains $domain.Domain) {
        $currentRule.SenderDomainIs += $domain.Domain
        Set-TransportRule -Identity "Whitelist Multiple Domains" -SenderDomainIs $currentRule.SenderDomainIs
        Write-Host "Added $($domain.Domain) to the rule. ($currentIndex of $totalDomains added)"
    } else {
        Write-Host "$($domain.Domain) is already in the rule. Skipping..."
    }
}
```


