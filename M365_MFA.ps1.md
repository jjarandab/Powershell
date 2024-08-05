# M365_MFS.ps1 Script

``` powershell
#Install-Module MSOnline
#install-module AzureAD


Connect-MsolService


Function MFA-Report {
$Report = @()
$i = 0
$Accounts = (Get-MsolUser -All | ? {$_.StrongAuthenticationMethods -ne $Null} | Sort DisplayName)
$Tenant = Get-MsolCompanyInformation | Select DisplayName
$TenantName = $Tenant.DisplayName
$timestamp = Get-Date -UFormat %Y%m%d-%H%M
$reportfile = "C:\MFAUsers-$TenantName-$timestamp.csv"


ForEach ($Account in $Accounts){
   Write-Host "Processing" $Account.DisplayName
   $i++
   $Methods = $Account | Select -ExpandProperty StrongAuthenticationMethods
   $MFA = $Account | Select -ExpandProperty StrongAuthenticationUserDetails
   $State = $Account | Select -ExpandProperty StrongAuthenticationRequirements
   $Methods | ForEach { If ($_.IsDefault -eq $True) {$Method = $_.MethodType}}
   If ($State.State -ne $Null) {$MFAStatus = $State.State}
      Else {$MFAStatus = "Disabled"}

      # Generate contents of MFA Types Column
$loop_count = 0;
$MFATypes = "";
      $max_loop_count = ($Account.StrongAuthenticationMethods.methodtype).count - 1
       $authentication_methods = @($Account.StrongAuthenticationMethods.methodtype | sort | out-string) -split "`n"
       
       
          while ($loop_count -le $max_loop_count)
          {
             if ($loop_count -lt $max_loop_count)
             {
                $MFATypes += $authentication_methods[$loop_count].Replace("`r",", ")
             }
             else 
             {
                $MFATypes += $authentication_methods[$loop_count]
             }
             # increase counter variable
             $loop_count++
          }

   $ReportLine = [PSCustomObject]@{
       User      = $Account.DisplayName
       UPN       = $Account.UserPrincipalName
       DefaultMFAMethod = $Method
       MFAPhone  = $MFA.PhoneNumber
	   MFAaltPhone = $MFA.AlternativePhoneNumber
       MFAEmail  = $MFA.Email
       MFAStatus = $MFAStatus

       "MFA Types" = $MFATypes
      

      }
   $Report += $ReportLine      }
Write-Host $i "accounts are MFA-enabled"
 


$Report | Export-CSV -Path $reportfile -NoTypeInformation

}

MFA-Report
```

