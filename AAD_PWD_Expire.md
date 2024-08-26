### How to check the expiration policy for a password

```powershell
# Install & Import Rerquired Modules
Install-Module -Name Microsoft.Graph
Import-Module -Name Microsoft.Graph

# Connect
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All"

# To see the Password never expires setting for all users
Get-MGuser -All -Property UserPrincipalName, PasswordPolicies | Select-Object UserprincipalName,@{
    N="PasswordNeverExpires";E={$_.PasswordPolicies -contains "DisablePasswordExpiration"}
 }

 # To set the password of one user to never expire
 Update-MgUser -UserId <user ID> -PasswordPolicies DisablePasswordExpiration

 # To set the passwords of ALL the users in an organization to never expire
 Get-MGuser -All | Update-MgUser -PasswordPolicies DisablePasswordExpiration

 # To set the password of one user so that the password expires
 Update-MgUser -UserId <user ID> -PasswordPolicies None

 # To set the passwords of all users in the organization so that they expire
 Get-MGuser -All | Update-MgUser -PasswordPolicies None
```


