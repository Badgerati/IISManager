# IISManager

This is a lightweight PowerShell module to help manage IIS instances, with support for working in PowerShell Core on Windows (including the Ubuntu prompt on Windows).

Unlike other modules, this module has no dependency on any DLLs. The only dependency is that you have IIS installed on the server (or your machine).

There is also support for binding certificates to websites, and sharing directories.

NOTE: This is a work in progress, so there will be bugs/changes. This will be on the PowerShell Gallery once stable. Feel free to contribute.

## Functions

### Application Pools

* Get-IISMAppPools
* New-IISMAppPool
* Remove-IISMAppPool
* Reset-IISMAppPool
* Reset-IISMServer
* Restart-IISMAppPool
* Start-IISMAppPool
* Stop-IISMAppPool
* Test-IISMAppPool
* Test-IISMAppPoolRunning
* Update-IISMAppPool
* Update-IISMAppPoolProcessModel
* Update-IISMAppPoolRecycling

### Apps

* Get-IISMApps
* New-IISMApp
* Remove-IISMApp
* Test-IISMApp
* Update-IISMApp

### Directories

* Get-IISMDirectories
* Get-IISMDirectoryShare
* Mount-IISMDirectoryShare
* New-IISMDirectory
* Remove-IISMDirectory
* Remove-IISMDirectoryShare
* Test-IISMDirectory
* Test-IISMDirectoryShare
* Update-IISMDirectory
* Update-IISMDirectoryPhysicalPaths

### Sites

* Add-IISMSiteBinding
* Edit-IISMSiteAppPool
* Edit-IISMSitePhysicalPath
* Get-IISMSiteAppPool
* Get-IISMSiteBindingCertificate
* Get-IISMSiteBindings
* Get-IISMSitePhysicalPath
* Get-IISMSites
* New-IISMSite
* Remove-IISMSite
* Remove-IISMSiteBinding
* Remove-IISMSiteDefaultBinding
* Remove-IISMSiteBindingCertificate
* Restart-IISMSite
* Set-IISMSiteBindingCertificate
* Start-IISMSite
* Stop-IISMSite
* Test-IISMSite
* Test-IISMSiteBindingCertificate
* Test-IISMSiteRunning
