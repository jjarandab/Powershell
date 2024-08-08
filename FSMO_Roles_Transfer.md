FSMO DC Roles Transfer

```powershell
### Get Assigned Roles ###
# Get domain level FSMO roles & forest level FSMO roles
get-addomain | select InfrastructureMaster, PDCEmulator, RIDMaster | Get-ADForest | select DomainNamingMaster, SchemaMaster

# Get forest level FSMO roles
Get-ADForest | select DomainNamingMaster, SchemaMaster

### Transfer Roles ###
#Transfer PDCEmulator
Move-ADDirectoryServerOperationMasterRole -Identity "ARANDA-DC02" PDCEmulator
#Transfer RIDMaster
Move-ADDirectoryServerOperationMasterRole -Identity "ARANDA-DC02" RIDMaster
#Transfer InfrastrctureMaster
Move-ADDirectoryServerOperationMasterRole -Identity "ARANDA-DC02" Infrastructuremaster
#Transfer DomainNamingMaster
Move-ADDirectoryServerOperationMasterRole -Identity "ARANDA-DC02" DomainNamingmaster
#Transfer SchemaMaster
Move-ADDirectoryServerOperationMasterRole -Identity "ARANDA-DC02" SchemaMaster

#Single Liner Command
Move-ADDirectoryServerOperationMasterRole -Identity ARANDA-DC02 –OperationMasterRole DomainNamingMaster,PDCEmulator,RIDMaster,SchemaMaster,InfrastructureMaster
#OR
Move-ADDirectoryServerOperationMasterRole ARANDA-DC01 –OperationMasterRole 0,1,2,3,4

#If "Move-ADDirectoryServerOperationMasterRole : Access is denied"; run as domain administrator account
$cred = Get-Credential
Move-ADDirectoryServerOperationMasterRole ARANDA-DC01 -OperationMasterRole SchemaMaster -Verbose -Force -Credential $cred
```
