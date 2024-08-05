# 2019SrvSetup.ps1

``` powershell
#Set NTP time
w32tm /config /manualpeerlist:ca.pool.ntp.org /syncfromflags:manual
stop-service w32time
start-service w32time

#Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

#Disable firewall for all profiles
netsh advfirewall set allprofiles state off

#Set time zone to Eastern
Tzutil /s "Eastern Standard Time"

#Set Local Admin password to never expire
#gwmi Win32_UserAccount -Filter "name = 'Administrator'" | swmi -Arguments @{PasswordExpires = 0}


#Enable Remote Desktop
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0

#Set Background to solid colour
Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name 'Background' -Value "45 125 154"
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value ""
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers' -Name BackgroundType -Value 1

#######Set Icon Size########
$IconSize = 32
IF(Test-Path -Path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop)
{
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -Name IconSize -Value $IconSize
}
ELSEIF(Test-Path -Path 'HKCU:\Control Panel\Desktop\WindowMetrics')
{
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'Shell Icon Size' -Value $IconSize
}  
#Restart Explorer to change it immediately  
Stop-Process -name explorer
###############################

## ==============================================
## Show Desktop Icons
## ==============================================

$ErrorActionPreference = "SilentlyContinue"
If ($Error) {$Error.Clear()}
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
If (Test-Path $RegistryPath) {
       $Res = Get-ItemProperty -Path $RegistryPath -Name "HideIcons"
       If (-Not($Res)) {
              New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       $Check = (Get-ItemProperty -Path $RegistryPath -Name "HideIcons").HideIcons
       If ($Check -NE 0) {
              New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
}
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
If (-Not(Test-Path $RegistryPath)) {
       New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "HideDesktopIcons" -Force | Out-Null
       New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null
}
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
If (-Not(Test-Path $RegistryPath)) {
       New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null
}
If (Test-Path $RegistryPath) {
       ## -- My Computer
       $Res = Get-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
       If (-Not($Res)) {
              New-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       $Check = (Get-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}")."{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
       If ($Check -NE 0) {
              New-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       ## -- User's Files
       $Res = Get-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
       If (-Not($Res)) {
              New-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       $Check = (Get-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}")."{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
       If ($Check -NE 0) {
              New-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       ## -- Recycle Bin
       $Res = Get-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}"
       If (-Not($Res)) {
              New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       $Check = (Get-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}")."{645FF040-5081-101B-9F08-00AA002F954E}"
       If ($Check -NE 0) {
              New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       ## -- Network
       $Res = Get-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
       If (-Not($Res)) {
              New-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
       $Check = (Get-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")."{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
       If ($Check -NE 0) {
              New-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Value "0" -PropertyType DWORD -Force | Out-Null
       }
}
If ($Error) {$Error.Clear()}

##########################################Visual Graphic Changes############################################
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -name VisfualFXSetting -value 00000002
Set-ItemProperty -path "HKCU:\\Control Panel\Desktop\WindowMetrics" -name MinAnimate -value 0
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name TaskbarAnimations -value 0
###Set-ItemProperty -path "HKLM:\\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name TaskbarAnimations -value -
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\DWM" -name CompositionPolicy -Value 0
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\DWM" -name ColorizationOpaqueBlend -Value 0
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\DWM" -name ColorPrevalence -value 1
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\DWM" -name AlwaysHibernateThumbnails -value 00000000
New-Item -Name Explorer -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Policies" -type Directory
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name DisableThumbnails -value 00000001
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name ListviewAlphaSelect -value 0
Set-ItemProperty -path "HKCU:\\Control Panel\Desktop" -name DragFullWindows -value 0
Set-ItemProperty -path "HKCU:\\Control Panel\Desktop" -name FontSmoothing -value 0
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\ThemeManager" -name ThemeActive -value 0
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name EnableTransparency -value 0
Set-ItemProperty -path "HKCU:\\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name ColorPrevalence -value 1

#############################################################################################################

#####Disable Server Manager Task on Login######
schtasks /change /tn "microsoft\Windows\Server Manager\ServerManager" /Disable | Out-Host

####Disable VMQ for all NICs####
Get-NetAdapterVMQ | Set-NetAdapterVMQ -Enabled $False

### Disable IE First Run Wizard and RSS Feeds
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1

### Turn off Windows SideShow
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sideshow" -Name "Disabled" -Value 1

### Disable UAC secure desktop prompt
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0

### Disable New Network dialog
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force

### Disable AutoUpdate of drivers from WU
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "searchorderConfig" -Value 0

### Disable monitor time out (never)
powercfg -change -monitor-timeout-ac 0

# Disable Action Center Icon
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAHealth" -Value 1

# Disable IE Persistent Cache 
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Name "Persistent" -Value 0
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Feeds" -Name "SyncStatus" -Value 0

# Disable screensavers
Set-RegistryKey -Path "HKUDefaultUser:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 0
Set-RegistryKey -Path "HKUDefaultUser:\Control Panel\Desktop\" -Name "ScreenSaveActive" -Value 0
Set-RegistryKey -Path "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 0
# Don't show window contents when dragging 
Set-RegistryKey -Path "HKUDefaultUser:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0
# Don't show window minimize/maximize animations
Set-RegistryKey -Path "HKUDefaultUser:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
# Enable font smoothing 
Set-RegistryKey -Path "HKUDefaultUser:\Control Panel\Desktop" -Name "FontSmoothing" -Value 1
# Disable Blur on Login Screen
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name DisableAcrylicBackgroundOnLogon -PropertyType DWord -Value 1 -Force
# Disable most other visual effects 
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 3
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewWatermark" -Value 0
Set-RegistryKey -Path "HKUDefaultUser:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0
Set-RegistryKey -Path "HKUDefaultUser:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x01,0x80)) -PropertyType "Binary"
```

