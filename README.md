# IISManager

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/Badgerati/IISManager/master/LICENSE.txt)
[![PowerShell](https://img.shields.io/powershellgallery/dt/iismanager.svg?label=PowerShell&colorB=085298)](https://www.powershellgallery.com/packages/IISManager)

This is a lightweight PowerShell module to help manage IIS instances, with support for working in PowerShell Core on Windows (including the Ubuntu prompt on Windows).

Unlike other modules, this module has no dependency on any DLLs. The only dependency is that you have IIS installed on the server (or your machine).

There is also support for binding certificates to websites, and sharing directories.

Feel free to contribute.

## Install

```powershell
Install-Module -Name IISManager
Import-Module -Name IISManager
```

## Functions

### Application Pools

* Get-IISMAppPool
* Get-IISMAppPools
* New-IISMAppPool
* Remove-IISMAppPool
* Reset-IISMAppPool
* Restart-IISMAppPool
* Start-IISMAppPool
* Stop-IISMAppPool
* Test-IISMAppPool
* Test-IISMAppPoolRunning
* Update-IISMAppPool
* Update-IISMAppPoolProcessModel
* Update-IISMAppPoolRecycling

### Apps

* Get-IISMApp
* New-IISMApp
* Remove-IISMApp
* Test-IISMApp
* Update-IISMApp

### Directories

* Get-IISMDirectory
* Get-IISMDirectoryShare
* Mount-IISMDirectoryShare
* New-IISMDirectory
* Remove-IISMDirectory
* Remove-IISMDirectoryShare
* Set-IISMDirectoryCredentials
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
* Get-IISMSite
* Get-IISMSites
* New-IISMSite
* Remove-IISMSite
* Remove-IISMSiteBinding
* Remove-IISMSiteBindings
* Remove-IISMSiteDefaultBinding
* Remove-IISMSiteBindingCertificate
* Reset-IISMSiteAppPool
* Restart-IISMSite
* Set-IISMSiteBindingCertificate
* Start-IISMSite
* Stop-IISMSite
* Test-IISMSite
* Test-IISMSiteBinding
* Test-IISMSiteBindingCertificate
* Test-IISMSiteRunning

### Logging

* Add-IISMSiteCustomLogField
* Add-IISMSiteLogField
* Clear-IISMSiteCustomLogFields
* Clear-IISMSiteLogFields
* Get-IISMSiteCustomLogFields
* Get-IISMSiteLogFields
* Get-IISMSiteLogFormat
* Get-IISMSiteLogging
* Get-IISMSiteLogPath
* Get-IISMSiteLogPeriod
* Remove-IISMSiteCustomLogField
* Remove-IISMSiteLogField
* Set-IISMSiteLogFields
* Set-IISMSiteLogPath
* Set-IISMSiteLogPeriod
* Test-IISMSiteCustomLogField
* Test-IISMSiteLogField


### FTP

* Add-IISMFtpDirectoryIPSecurity
* Add-IISMFtpDirectoryAuthorization
* Add-IISMFtpServerCustomAuthentication
* Add-IISMFtpSiteCustomAuthentication
* Add-IISMFtpSiteLogField
* Clear-IISMFtpSiteLogFields
* Disable-IISMFtpSiteAuthentication
* Enable-IISMFtpSiteAuthentication
* Get-IISMFtpDirectoryAuthorization
* Get-IISMFtpDirectoryIPSecurity
* Get-IISMFtpServerCustomAuthentication
* Get-IISMFtpServerCustomAuthenticationProvider
* Get-IISMFtpSiteLogging
* Get-IISMFtpSiteLogFields
* Get-IISMFtpSiteLogPath
* Get-IISMFtpSiteLogPeriod
* Register-IISMFtpServerCustomAuthenticationProvider
* Remove-IISMFtpDirectoryAuthorization
* Remove-IISMFtpDirectoryIPSecurity
* Remove-IISMFtpServerCustomAuthentication
* Remove-IISMFtpSiteCustomAuthentication
* Remove-IISMFtpSiteLogField
* Set-IISMFtpDirectoryIPSecurityUnlisted
* Set-IISMFtpSiteLogFields
* Set-IISMFtpSiteLogPath
* Set-IISMFtpSiteLogPeriod
* Set-IISMFtpSiteSslPolicy
* Set-IISMFtpSiteUserIsolation
* Test-IISMFtpSiteLogField
* Test-IISMSiteIsFtp
* Unregister-IISMFtpServerCustomAuthenticationProvider

### Misc

* Get-IISMCertificateThumbprint
* Invoke-IISMAppCommand
* New-IISMCredentials
* Reset-IISMServer

## ToDo

* Hosts file control
* Folder permissions via ACL
