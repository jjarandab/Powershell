# Local Commands

## Free Disk Space

Print Used Space

``` powershell
Get-WmiObject -Class Win32_LogicalDisk | Select-Object -Property DeviceID, VolumeName, @{Label='FreeSpace (Gb)'; expression={($_.FreeSpace/1GB).ToString('F2')}}, @{Label='Total (Gb)'; expression={($_.Size/1GB).ToString('F2')}}, @{label='FreePercent'; expression={[Math]::Round(($_.freespace / $_.size) * 100, 2)}}|ft
```

## PasswordNeverExpires

``` powershell
get-aduser -filter * -properties Name, PasswordNeverExpires | where { $.passwordNeverExpires -eq "true" } | where {$.enabled -eq "true"} | Format-Table -Property Name, UserPrincipalName, Enabled, PasswordNeverExpires -AutoSize
```

``` powershell
get-aduser -filter * -properties Name, PasswordNeverExpires | Format-Table -Property Name, UserPrincipalName, Enabled, PasswordNeverExpires -AutoSize
```

