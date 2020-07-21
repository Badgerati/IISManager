function ConvertTo-IISMSiteObject
{
    param (
        [Parameter()]
        $Sites,

        [switch]
        $Quick
    )

    if ($Quick) {
        return (ConvertTo-IISMSiteQuickObject -Sites $Sites)
    }

    $apps = Get-IISMApp
    $mapped = @()

    foreach ($site in $Sites) {
        # get app info
        $_apps = @(foreach ($app in $apps) {
            if (($null -ne $app) -and ($app.SiteName -ieq $site.site.name)) {
                $app
            }
        })

        # get binding info
        $_bindings = @(ConvertTo-IISMBindingObject -Site $site)

        # get logging info
        $_logging = Get-IISMSiteLogging -Name $site.site.name

        # get the ftp info - but only if the protocol is ftp
        $_ftp = $null
        if ($_bindings.Protocol -icontains 'ftp') {
            $_ftp = ConvertTo-IISMFtpServerObject -SiteName $site.site.name -FtpServer $site.site.ftpServer
        }

        # server auto start
        $serverAutoStart = (($null -eq $site.site.serverAutoStart) -or ('true' -ieq $site.site.serverAutoStart))

        # build site object
        $obj = @{
            ID = $site.site.id
            Name = $site.site.name
            Bindings = @($_bindings)
            State = $site.state
            Apps = $_apps
            Limits = $null
            Logging = $_logging
            TraceFailedRequestsLogging = $null
            Hsts = $null
            ApplicationDefaults = $null
            Ftp = $_ftp
            ServerAutoStart = $serverAutoStart
        }

        $mapped +=  $obj
    }

    return $mapped
}

function ConvertTo-IISMBindingObject
{
    param(
        [Parameter()]
        $Site
    )

    if ($null -eq $Site) {
        return @()
    }

    return @(foreach ($binding in $Site.site.bindings.binding) {
        if ($null -ne $binding) {
            Get-IISMSiteBindingInformation -Binding $binding
        }
    })
}

function ConvertTo-IISMSiteQuickObject
{
    param (
        [Parameter()]
        $Sites
    )

    $mapped = @()

    foreach ($site in $Sites) {
        $obj = @{
            ID = $site.site.id
            Name = $site.site.name
            Bindings = $null
            State = $site.state
            Apps = $null
            Limits = $null
            Logging = $null
            TraceFailedRequestsLogging = $null
            Hsts = $null
            ApplicationDefaults = $null
            Ftp = $null
        }

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMSiteCustomLogFieldObject
{
    param (
        [Parameter()]
        $Fields
    )

    $mapped = @()

    foreach ($field in $Fields) {
        $obj = @{
            Name = $field.logFieldName
            Source = $field.sourceName
            Type = $field.sourceType
        }

        $mapped +=  $obj
    }

    return $mapped
}

function ConvertTo-IISMSiteLoggingObject
{
    param (
        [Parameter()]
        $Fields,

        [Parameter()]
        $CustomFields,

        [Parameter()]
        $Format,

        [Parameter()]
        $Path,

        [Parameter()]
        $Period
    )

    $obj = @{
        Fields = $Fields
        CustomFields = $CustomFields
        Format = $Format
        Path = $Path
        Period = $Period
    }

    return $obj
}

function ConvertTo-IISMFtpSiteLoggingObject
{
    param (
        [Parameter()]
        $Fields,

        [Parameter()]
        $Path,

        [Parameter()]
        $Period
    )

    $obj = @{
        Fields = $Fields
        Path = $Path
        Period = $Period
    }

    return $obj
}

function ConvertTo-IISMAppPoolObject
{
    param (
        [Parameter()]
        $AppPools
    )

    $mapped = @()

    foreach ($pool in $AppPools) {
        $poolInfo = $pool.add

        $idleTimeout = '00:00:00'
        if (![string]::IsNullOrWhiteSpace($poolInfo.processModel.idleTimeout)) {
            $idleTimeout = $poolInfo.processModel.idleTimeout
        }

        $obj = @{
            Name = $pool.'APPPOOL.NAME'
            PipelineMode = $pool.PipelineMode
            RuntimeVersion = $pool.RuntimeVersion
            State = $pool.state
            ProcessModel = @{
                Credentials = (New-IISMCredentials -Username $poolInfo.processModel.userName -Password $poolInfo.processModel.password)
                IdentityType = $poolInfo.processModel.identityType
                MaxProcesses = [int]$poolInfo.processModel.maxProcesses
                IdleTimeout = @{
                    Duration = [timespan]$idleTimeout
                    Action = $poolInfo.processModel.idleTimeoutAction
                }
            }
            Recycling = $null
            Failure = $null
            CPU = $null
            EnvironmentVariables = $null
        }

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMAppObject
{
    param (
        [Parameter()]
        $Apps,

        [switch]
        $Quick
    )

    $mapped = @()

    foreach ($app in $Apps) {
        if (!$Quick) {
            $_pool = Get-IISMAppPool -Name $app.'APPPOOL.NAME'
            $_info = Split-IISMAppName -AppName $app.'APP.NAME'
            $_dirs = Get-IISMDirectory -SiteName $_info.SiteName -AppName $_info.AppName
        }

        $obj = @{
            Name = $app.'APP.NAME'
            Path = $app.path
            AppPool = $_pool
            SiteName = $app.'SITE.NAME'
            Directories = $_dirs
        }

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMDirectoryObject
{
    param(
        [Parameter()]
        $Directories,

        [switch]
        $Quick
    )

    $mapped = @()

    foreach ($dir in $Directories) {
        # get the ftp info
        $_dirName = $dir.'VDIR.NAME'
        $_siteName = (Split-IISMDirectoryName -DirName $_dirName).SiteName

        if (!$Quick -and (Test-IISMSiteIsFtp -Name $_siteName)) {
            $_ftp = @{
                Authorization = (Get-IISMFtpDirectoryAuthorizationInternal -Name $_dirName)
                IPSecurity = (Get-IISMFtpDirectoryIPSecurityInternal -Name $_dirName)
            }
        }

        # build the dir object
        $obj = @{
            Name = $dir.'VDIR.NAME'
            PhysicalPath = $dir.physicalPath
            Path = $dir.path
            AppName = $dir.'APP.NAME'
            Credentials = (New-IISMCredentials -Username $dir.virtualDirectory.userName -Password $dir.virtualDirectory.password)
            Ftp = $_ftp
        }

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMFtpServerObject
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        $FtpServer
    )

    if ($null -eq $FtpServer) {
        return $null
    }

    $_security = ConvertTo-IISMFtpServerSecurityObject -Security $FtpServer.security

    return @{
        Connections = $null
        Security = $_security
        CustomFeatures = @{
            Providers = $null
        }
        Messages = $null
        FileHandling = $null
        FirewallSupport = $null
        UserIsolation = @{
            Mode = Protect-IISMValue -Value1 $FtpServer.userIsolation.mode -Value2 'None'
            ActiveDirectory = @{
                Credentials = (New-IISMCredentials -Username $FtpServer.userIsolation.activeDirectory.adUserName -Password $FtpServer.userIsolation.activeDirectory.adPassword)
            }
        }
        DirectoryBrowse = $null
        LogFile = (Get-IISMFtpSiteLogging -Name $SiteName)
    }
}

function ConvertTo-IISMFtpServerSecurityObject
{
    param(
        [Parameter()]
        $Security
    )

    if ($null -eq $Security) {
        return $null
    }

    # ftp ssl and cert
    $_ssl = @{
        Certificate = (Get-IISMSiteBindingCertificate -Thumbprint $Security.ssl.serverCertHash)
        ControlChannelPolicy = $Security.ssl.controlChannelPolicy
        DataChannelPolicy = $Security.ssl.dataChannelPolicy
    }

    # ftp auth
    $_auth = @{
        Anonymous = @{
            Enabled = ($Security.authentication.anonymousAuthentication.enabled -ieq 'true')
            Credentials = (New-IISMCredentials -Username $Security.authentication.anonymousAuthentication.username -Password $Security.authentication.anonymousAuthentication.password)
            Domain = $Security.authentication.anonymousAuthentication.defaultLogonDomain
            LogonMethod = $Security.authentication.anonymousAuthentication.logonMethod
        }
        Basic = @{
            Enabled = ($Security.authentication.basicAuthentication.enabled -ieq 'true')
            Domain = $Security.authentication.basicAuthentication.defaultLogonDomain
            LogonMethod = $Security.authentication.basicAuthentication.logonMethod
        }
        ClientCertificate = @{
            Enabled = ($Security.authentication.clientCertAuthentication.enabled -ieq 'true')
        }
        Custom = @{
            Providers = @(foreach ($provider in $Security.authentication.customAuthentication.providers.add) {
                @{
                    Enabled = ($provider.enabled -ieq 'true')
                    Name = $provider.name
                }
            })
        }
    }

    # ftp security obj
    return @{
        DataChannelSecurity = $null
        CommandFiltering = $null
        Ssl = $_ssl
        SslClientCertificates = $null
        Authentication = $_auth
        CustomAuthorization = @{
            Provider = @{
                Enabled = [bool]$Security.customAuthorization.provider.enabled
                Name = $Security.customAuthorization.provider.name
            }
        }
    }
}

function ConvertTo-IISMFtpAuthorizationObject
{
    param(
        [Parameter()]
        $Section
    )

    $mapped = @{
        Rules = @()
    }

    foreach ($rule in $Section.add) {
        $obj = @{
            AccessType = $rule.accessType
            Users = @($rule.users -split ',').Trim()
            Roles = @($rule.roles -split ',').Trim()
            Permissions = @($rule.permissions -split ',').Trim()
            FullAccess = $false
        }

        $obj.FullAccess = (($obj.Permissions -icontains 'read') -and ($obj.Permissions -icontains 'write'))
        $mapped.Rules += $obj
    }

    return $mapped
}

function ConvertTo-IISMFtpIPSecurityObject
{
    param(
        [Parameter()]
        $Section
    )

    $mapped = @{
        AllowUnlisted = ($Section.allowUnlisted -ieq 'true')
        Rules = @()
    }

    foreach ($rule in $Section.add) {
        $accessType = 'Allow'
        if ($rule.allowed -ieq 'false') {
            $accessType = 'Deny'
        }

        $subnetMask = $rule.subnetMask
        if ([string]::IsNullOrWhiteSpace($subnetMask)) {
            $subnetMask = '255.255.255.255'
        }

        $obj = @{
            AccessType = $accessType
            IPAddress = $rule.ipAddress
            SubnetMask = $subnetMask
        }

        $mapped.Rules += $obj
    }

    return $mapped
}