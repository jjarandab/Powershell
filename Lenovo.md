# Lenovo Drivers

Orchestrate driver, BIOS/UEFI and firmware updates for Lenovo computers - with PowerShell!

**Installation**

```powershell
Install-Module -Name 'LSUClient'
```

**Show Available Updates**

```powershell
Get-LSUpdate
```

**Find and install available updates:**

```powershell
$updates = Get-LSUpdate
$updates | Install-LSUpdate -Verbose
```

Ref:

[GitHub - jantari/LSUClient: Orchestrate driver, BIOS/UEFI and firmware updates for Lenovo computers 👨‍💻](https://github.com/jantari/LSUClient)


