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
        $_bindings = @(foreach ($binding in $site.site.bindings.binding) {
            if ($null -ne $binding) {
                Get-IISMSiteBindingInformation -Binding $binding
            }
        })

        # get logging info
        $_logging = Get-IISMSiteLogging -Name $site.site.name

        # get the ftp info - but only if the protocol is ftp
        $_ftp = $null
        if ($_bindings.Protocol -icontains 'ftp') {
            $_ftp = ConvertTo-IISMFtpServerObject -FtpServer $site.site.ftpServer
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
            FTP = $_ftp
            ServerAutoStart = $serverAutoStart
        }

        $mapped +=  $obj
    }

    return $mapped
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
            FTP = $null
        }

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMFtpServerObject
{
    param(
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
        LogFile = $null
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
            Enabled = ([bool]$Security.authentication.anonymousAuthentication.enabled)
            Credentials = (New-IISMCredentials -Username $Security.authentication.anonymousAuthentication.username -Password $Security.authentication.anonymousAuthentication.password)
            Domain = $Security.authentication.anonymousAuthentication.defaultLogonDomain
            LogonMethod = $Security.authentication.anonymousAuthentication.logonMethod
        }
        Basic = @{
            Enabled = ([bool]$Security.authentication.basicAuthentication.enabled)
            Domain = $Security.authentication.basicAuthentication.defaultLogonDomain
            LogonMethod = $Security.authentication.basicAuthentication.logonMethod
        }
        ClientCertificate = @{
            Enabled = ([bool]$Security.authentication.clientCertAuthentication.enabled)
        }
        Custom = @{
            Providers = $null
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
                Enabled = ([bool]$Security.customAuthorization.provider.enabled)
                Name = $Security.customAuthorization.provider.name
            }
        }
    }
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

function ConvertTo-IISMAppPoolObject
{
    param (
        [Parameter()]
        $AppPools
    )

    $mapped = @()

    foreach ($pool in $AppPools) {
        $poolInfo = $pool.add

        $obj = @{
            Name = $pool.'APPPOOL.NAME'
            PipelineMode = $pool.PipelineMode
            RuntimeVersion = $pool.RuntimeVersion
            State = $pool.state
            ProcessModel = @{
                Credentials = (New-IISMCredentials -Username $poolInfo.processModel.userName -Password $poolInfo.processModel.password)
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

        [Parameter()]
        $AppPools,

        [Parameter()]
        $Directories
    )

    $mapped = @()

    foreach ($app in $Apps) {
        $_pool = @(foreach ($pool in $AppPools) {
            if ($pool.Name -ieq $app.'APPPOOL.NAME') {
                $pool
                break
            }
        })[0]

        $_dir = @(foreach ($dir in $Directories) {
            if ($dir.AppName -ieq $app.'APP.NAME') {
                $dir
                break
            }
        })[0]

        $obj = @{
            Name = $app.'APP.NAME'
            Path = $app.path
            AppPool = $_pool
            SiteName = $app.'SITE.NAME'
            Directory = $_dir
        }

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMDirectoryObject
{
    param (
        [Parameter()]
        $Directories
    )

    $mapped = @()

    foreach ($dir in $Directories) {
        $obj = @{
            Name = $dir.'VDIR.NAME'
            PhysicalPath = $dir.physicalPath
            Path = $dir.path
            AppName = $dir.'APP.NAME'
        }

        $mapped += $obj
    }

    return $mapped
}
