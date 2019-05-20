# IISManager

This is a lightweight PowerShell module to manage IIS instances, with support for working in PowerShell Core on Windows (including the Ubuntu prompt on Windows).

Unlike other modules, this module has no dependency on any DLLs. The only dependency is that you have IIS installed on the server.

## Functions

### Application Pools

* Get-IISAppPools
* New-IISAppPool
* Remove-IISAppPool
* Reset-IISAppPool
* Restart-IISAppPool
* Start-IISAppPool
* Stop-IISAppPool
* Test-IISAppPool
* Test-IISAppPoolRunning

### Apps

* Get-IISApps
* Remove-IISApp
* Test-IISApp

### Directories

* Get-IISDirectories
* Remove-IISDirectory
* Test-IISDirectory

### Sites

* Get-IISSites
* Get-IISSiteBindings
* Get-IISSitePhysicalPath
* New-IISSiteBinding
* Remove-IISSite
* Remove-IISSiteBinding
* Restart-IISSite
* Start-IISSite
* Stop-IISSite
* Test-IISSite
* Test-IISSiteRunning


