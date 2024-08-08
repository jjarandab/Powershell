# Local Commands

## Free Disk Space

Print Used Space

```powershell
Get-WmiObject -Class Win32_LogicalDisk | Select-Object -Property DeviceID, VolumeName, @{Label='FreeSpace (Gb)'; expression={($_.FreeSpace/1GB).ToString('F2')}}, @{Label='Total (Gb)'; expression={($_.Size/1GB).ToString('F2')}}, @{label='FreePercent'; expression={[Math]::Round(($_.freespace / $_.size) * 100, 2)}}|ft

Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue

#CMD 
fsutil volume diskfree c: 

cleanmgr /sagerun 
cleanmgr /verylowdisk /c 
del %temp%\*.* /s /q 
del C:\Windows\prefetch\*.*/s/q 
```

## PasswordNeverExpires

```powershell
get-aduser -filter * -properties Name, PasswordNeverExpires | where { $.passwordNeverExpires -eq "true" } | where {$.enabled -eq "true"} | Format-Table -Property Name, UserPrincipalName, Enabled, PasswordNeverExpires -AutoSize
```

```powershell
get-aduser -filter * -properties Name, PasswordNeverExpires | Format-Table -Property Name, UserPrincipalName, Enabled, PasswordNeverExpires -AutoSize
```

## System Health

```powershell
Name, Type, HealthStatus, OperationalStatus
Get-PhysicalDisk
Get-PhysicalDisk | Sort Size | FT FriendlyName, Size, MediaType, SpindleSpeed, HealthStatus, OperationalStatus -AutoSize
Temperature
Get-PhysicalDisk | Get-StorageReliabilityCounter | ft deviceid, temperature, wear -AutoSize
SMART
wmic diskdrive get status
PredictFailure
wmic /namespace:\\root\wmi path MSStorageDriver_FailurePredictStatus

#SSD / NVME
chkdsk /f /r /x
Chkdsk c: /r

#FILESYSTEM
sfc /scannow 
DISM.exe /Online /Cleanup-image /Restorehealth 

#FILESYSTEM 
chkntfs c: 
chkdsk /r c: 

# S.M.A.R.T Check 
wmic diskdrive get status 
wmic /namespace:\\root\wmi path MSStorageDriver_FailurePredictStatus 

#Get HDD Smart Status [CMD] 
wmic diskdrive get model,name,serialnumber,status 

# Determine Predictive Failure [CMD] 
wmic /namespace:\\root\wmi path MSStorageDriver_FailurePredictStatus 

# Is drive failing? [PowerShell] 
Get-WmiObject -namespace root\wmi -class MSStorageDriver_FailurePredictStatus
```

## WLAN

```powershell
#show wlan profiles
netsh wlan show profiles
#unhide Key content(wifi password)
netsh wlan show profile name="mars-tenants" key=clear
#check if password is present
netsh wlan show profile name="mars-tenants" | findstr /c key
#SHOW ALL WLAN PROFILES AND PASSWORDS
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear
```

## Windows Defender

```powershell
#Defender Enabled?
Get-MpComputerStatus
#Update Signature
Update-MpSignature
#Quick Scan / Full Scan
Start-MpScan -ScanType QuickScan
Start-MpScan -ScanType FullScan
#ustom Scan
Start-MpScan -ScanType CustomScan -ScanPath "C:\Users\user\Downloads"
#elete Active Threat
Remove-MpThreat
#et Preferences
Get-MpPreference
#xclude Folder
Set-MpPreference -ExclusionPath "C:\Users\user\Downloads"
#xclude File Type
Set-MpPreference -ExclusionExtension docx
#chedule Quick Scan
Set-MpPreference -ScanScheduleQuickScanTime 06:00:00
#chedule Full Scan
Set-MpPreference -ScanParameters 2
Set-MpPreference -RemediationScheduleDay SCAN-DAY
Set-MpPreference -RemediationScheduleTime 06:00:00

• 0 – Everyday
• 1 – Sunday
• 2 – Monday
• 3 – Tuesday
• 4 – Wednesday
• 5 – Thursday
• 6 – Friday
• 7 – Saturday
• 8 – Never

#sable Antivirus
Set-MpPreference -DisableRealtimeMonitoring $true
#nable External Drive Scan
Set-MpPreference -DisableRemovableDriveScanning $false
#isable Compressed File Scan
Set-MpPreference -DisableArchiveScanning $true
#isable Network Scan
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
# Reference: How to Manage Defender Antivirus with PowerShell
# https://www.youtube.com/watch?v=VAVWgE8HUcE
```

## Install HEIF and HEVC AppxBundle Extensions

```powershell
# bundle files can be downloaded from adguard link below, using other two URLs
# https://store.rg-adguard.net/
# https://apps.microsoft.com/detail/9nmzlz57r3t7?hl=en-us&gl=CA
# https://apps.microsoft.com/detail/9pmmsr1cgpwg?hl=en-us&gl=CA
Add-ProvisionedAppPackage -online -PackagePath "c:\pace-temp\Microsoft.HEVCVideoExtensions_2.1.1804.0_neutral_~_8wekyb3d8bbwe.AppxBundle" -skiplicense
Add-ProvisionedAppPackage -online -PackagePath "c:\pace-temp\Microsoft.HEIFImageExtension_1.1.861.0_neutral_~_8wekyb3d8bbwe.AppxBundle" -skiplicense
```

## Event Viewer Logs export

```powershell
New-Item -Path 'C:\temp\Event Viewer Logs' -ItemType Directory -ErrorAction SilentlyContinue 

$date = ( get-date ).ToString('yyyyMMdd') 

wevtutil.exe epl Application "C:\temp\Event Viewer Logs\$date Application.evtx" "/q:*[System[(Level=1  or Level=2) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /ow:true 

wevtutil.exe epl System "C:\temp\Event Viewer Logs\$date System.evtx" "/q:*[System[(Level=1  or Level=2) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /ow:true 

dir 'C:\temp\Event Viewer Logs' 

explorer.exe "C:\temp\Event Viewer Logs\" 

#clear eventlogs 

Clear-EventLog -LogName Application, System
```

NON-DC SERVERS

```powershell
#Are there no concerning accounts in the local Administrator group of each server? 
Get-LocalGroupMember -Group "Administrators" 
#CMD 
net localgroup Administrators 
```

DC SERVERS

```powershell
#Is there a working PACE Workstation Admin account present in AD with the last modify date within six months? 
Get-ADUser -Identity pacewkadmin -Properties * | Select -Property whenChanged 
#Are there no concerning accounts in the Administrators or Domain Admins groups within Active Directory? 
Get-ADGroupMember -Identity Administrators | Select -Property name Timeout /T 1 
Get-ADGroupMember -Identity "Domain Admins" | Select -Property name 
```

SQL Backup - Compress/Clean

```bash
forfiles.exe /p "E:\DailyDBBackup\SQL" /d -1 /m *.bak /c "cmd /c c:\progra~1\7-zip\7z.exe a -tzip @fname.zip @file" 
forfiles.exe /p "E:\DailyDBBackup\SQL" /m *.bak /d -1 /c "cmd /c del @file" 
forfiles.exe /p "E:\DailyDBBackup\SQL" /m *.zip /d -15 /c "cmd /c del @file"
```

[Dell Command | Configure | Dell Canada](https://www.dell.com/support/kbdoc/en-ca/000178000/dell-command-configure)

AcPwrRcvry when AC power is restored: On — System powers on after AC power is restored.

![](C:\Users\juan\AppData\Roaming\marktext\images\2024-08-08-09-18-22-image.png)

## Display Duplicate/Extend

```powershell
# Extend
%windir%\System32\DisplaySwitch.exe /extend
# Duplicate
%windir%\System32\DisplaySwitch.exe /clone 
```
