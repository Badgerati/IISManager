# IISManager

This is a lightweight PowerShell module to manage IIS instances, with support for working in PowerShell Core on Windows (including the Ubuntu prompt on Windows).

Unlike other modules, this module has no dependency on any DLLs. The only dependency is that you have IIS installed on the server.

## Functions

### Application Pools

* Get-IISMAppPools
* New-IISMAppPool
* Remove-IISMAppPool
* Reset-IISMAppPool
* Restart-IISMAppPool
* Start-IISMAppPool
* Stop-IISMAppPool
* Test-IISMAppPool
* Test-IISMAppPoolRunning

### Apps

* Get-IISMApps
* Remove-IISMApp
* Test-IISMApp

### Directories

* Get-IISMDirectories
* Remove-IISMDirectory
* Test-IISMDirectory

### Sites

* Get-IISMSites
* Get-IISMSiteBindings
* Get-IISMSitePhysicalPath
* New-IISMSiteBinding
* Remove-IISMSite
* Remove-IISMSiteBinding
* Restart-IISMSite
* Start-IISMSite
* Stop-IISMSite
* Test-IISMSite
* Test-IISMSiteRunning


