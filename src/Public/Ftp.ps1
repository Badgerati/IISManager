function Get-IISMFtpDirectoryAuthorization
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    return (Get-IISMFtpDirectoryAuthorizationInternal -Name $Name)
}

function Add-IISMFtpDirectoryAuthorization
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Read', 'Write')]
        [string[]]
        $Permission,

        [Parameter()]
        [string[]]
        $User,

        [Parameter()]
        [string[]]
        $Role,

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it already has the auth
    $current = (Get-IISMFtpDirectoryAuthorizationInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.Users -join ',') -ieq ($User -join ',') -and
        ($_.Roles -join ',') -ieq ($Role -join ',') -and
        ($_.Permissions -join ',') -ieq ($Permission -join ',')
    })

    if ($null -ne $check) {
        return
    }

    # add the auth
    $auth = Get-IISMFtpAuthorizationCommandString -AccessType $AccessType -Permission $Permission -User $User -Role $Role
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/authorization /+`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMFtpDirectoryAuthorization -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Remove-IISMFtpDirectoryAuthorization
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Read', 'Write')]
        [string[]]
        $Permission,

        [Parameter()]
        [string[]]
        $User,

        [Parameter()]
        [string[]]
        $Role,

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it doesnt have the auth
    $current = (Get-IISMFtpDirectoryAuthorizationInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.Users -join ',') -ieq ($User -join ',') -and
        ($_.Roles -join ',') -ieq ($Role -join ',') -and
        ($_.Permissions -join ',') -ieq ($Permission -join ',')
    })

    if ($null -eq $check) {
        return
    }

    # remove the auth
    $auth = Get-IISMFtpAuthorizationCommandString -AccessType $AccessType -Permission $Permission -User $User -Role $Role
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/authorization /-`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMFtpDirectoryAuthorization -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Get-IISMFtpDirectoryIPSecurity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    return (Get-IISMFtpDirectoryIPSecurityInternal -Name $Name)
}

function Add-IISMFtpDirectoryIPSecurity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [string]
        $IPAddress,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubnetMask = '255.255.255.255',

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it already has the auth
    $current = (Get-IISMFtpDirectoryIPSecurityInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.IPAddress -ieq $IPAddress) -and
        ($_.SubnetMask -ieq $SubnetMask)
    })

    if ($null -ne $check) {
        Write-Verbose "IP Security already exists"
        return
    }

    # add the auth
    $auth = Get-IISMFtpIPSecurityCommandString -AccessType $AccessType -IPAddress $IPAddress -SubnetMask $SubnetMask
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/ipSecurity /+`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMFtpDirectoryIPSecurity -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Remove-IISMFtpDirectoryIPSecurity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [string]
        $IPAddress,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubnetMask = '255.255.255.255',

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it doesnt have the auth
    $current = (Get-IISMFtpDirectoryIPSecurityInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.IPAddress -ieq $IPAddress) -and
        ($_.SubnetMask -ieq $SubnetMask)
    })

    if ($null -eq $check) {
        Write-Verbose "IP Security rule not found"
        return
    }

    # remove the auth
    $auth = Get-IISMFtpIPSecurityCommandString -AccessType $AccessType -IPAddress $IPAddress -SubnetMask $SubnetMask
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/ipSecurity /-`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMFtpDirectoryIPSecurity -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Set-IISMFtpDirectoryIPSecurityUnlisted
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # set unlisted type
    $allow = ($AccessType -ieq 'Allow')
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/ipSecurity /allowUnlisted:'$($allow)' /commit:apphost" -NoParse | Out-Null
}

function Get-IISMFtpServerCustomAuthenticationProvider
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Name
    )

    $result = Invoke-IISMAppCommand -Arguments 'list config /section:system.ftpServer/providerDefinitions' -NoError

    $providers = @(foreach ($provider in $result.CONFIG.'system.ftpServer-providerDefinitions'.add) {
        if (![string]::IsNullOrWhiteSpace($Name) -and ($provider.name -ine $Name)) {
            continue
        }

        @{
            Name = $provider.name
            Type = $provider.type
            ClassId = $provider.clsid
        }
    })

    return $providers
}

function Register-IISMFtpServerCustomAuthenticationProvider
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true, ParameterSetName='ClassId')]
        [string]
        $ClassId,

        [Parameter(Mandatory=$true, ParameterSetName='Type')]
        [string]
        $Type
    )

    # first, remove it, in case the details are different
    Unregister-IISMFtpServerCustomAuthenticationProvider -Name $Name

    # build the command for the auth type
    switch ($PSCmdlet.ParameterSetName) {
        'ClassId' {
            $auth = "[name='$($Name)',clsid='$($ClassId)']"
        }

        'Type' {
            $auth = "[name='$($Name)',type='$($Type)']"
        }
    }

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:system.ftpServer/providerDefinitions /+`"$($auth)`"" -NoParse | Out-Null
}

function Unregister-IISMFtpServerCustomAuthenticationProvider
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    # do nothing if it doesn't exist
    $auth = Get-IISMFtpServerCustomAuthenticationProvider -Name $Name
    if (($null -eq $auth) -or ($auth.Length -eq 0)) {
        return
    }

    # build the command
    $auth = "[name='$($Name)']"

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:system.ftpServer/providerDefinitions /-`"$($auth)`"" -NoParse | Out-Null
}

function Get-IISMFtpServerCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $ProviderName
    )

    $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
    $providers = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.ftpServer.security.authentication.customAuthentication.providers.add

    if (($null -eq $providers) -or ($providers.Length -eq 0)) {
        return $null
    }

    $_providers = @(foreach ($provider in $providers) {
        @{
            Name = $provider.name
            Enabled = ($provider.enabled -ieq 'true')
        }
    })

    if ([string]::IsNullOrWhiteSpace($ProviderName)) {
        return $_providers
    }

    return ($_providers | Where-Object { $_.Name -ieq $ProviderName })
}

function Add-IISMFtpServerCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $ProviderName,

        [switch]
        $Enable
    )

    # remove it first
    Remove-IISMFtpServerCustomAuthentication -ProviderName $ProviderName

    # build the command
    $_args = "/+`"siteDefaults.ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)',enabled='$($Enable.IsPresent)']`""

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:sites $($_args)" -NoParse | Out-Null
}

function Remove-IISMFtpServerCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $ProviderName
    )

    # do nothing if it doesn't exist
    $prov = Get-IISMFtpServerCustomAuthentication -ProviderName $ProviderName
    if (($null -eq $prov) -or ($prov.Length -eq 0)) {
        return
    }

    # build the command
    $_args = "/-`"siteDefaults.ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)']`""

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:sites $($_args)" -NoParse | Out-Null
}

function Set-IISMFtpSiteUserIsolation
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet('None', 'StartInUsersDirectory', 'IsolateAllDirectories', 'IsolateRootDirectoryOnly', 'ActiveDirectory')]
        [string]
        $Type,

        [Parameter()]
        [pscredential]
        $Credentials
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # error if the site isn't ftp
    if (!(Test-IISMSiteIsFtp -Name $Name)) {
        throw "Website '$($Name)' is not an FTP site"
    }

    # set the isolation mode
    $_args = "/ftpServer.userIsolation.mode:$($Type)"

    if ($Type -ieq 'ActiveDirectory') {
        if ($null -eq $Credentials) {
            throw "No credentials supplied when attempting to set the '$($Name)' user isolation type to ActiveDirectory"
        }

        $creds = Get-IISMCredentialDetails -Credentials $Credentials
        $_args += " /ftpServer.userIsolation.activeDirectory.userName:$($creds.username) /ftpServer.userIsolation.activeDirectory.password:$($creds.password)"
    }

    Invoke-IISMAppCommand -Arguments "set site '$($Name)' $($_args)" -NoParse | Out-Null
}

function Enable-IISMFtpSiteAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(ParameterSetName='Anonymous')]
        [switch]
        $Anonymous,

        [Parameter(ParameterSetName='Basic')]
        [switch]
        $Basic,

        [Parameter(ParameterSetName='ClientCertificate')]
        [switch]
        $ClientCertificate,

        [Parameter(ParameterSetName='Custom')]
        [switch]
        $Custom,

        [Parameter(ParameterSetName='Anonymous')]
        [pscredential]
        $Credentials,

        [Parameter(ParameterSetName='Anonymous')]
        [Parameter(ParameterSetName='Basic')]
        [string]
        $Domain,

        [Parameter(ParameterSetName='Anonymous')]
        [Parameter(ParameterSetName='Basic')]
        [string]
        $LogonMethod,

        [Parameter(Mandatory=$true, ParameterSetName='Custom')]
        [string]
        $ProviderName
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # error if the site isn't ftp
    if (!(Test-IISMSiteIsFtp -Name $Name)) {
        throw "Website '$($Name)' is not an FTP site"
    }

    # build the command for the auth type
    $_args = [string]::Empty

    switch ($PSCmdlet.ParameterSetName) {
        'Anonymous' {
            $_args = "/ftpServer.security.authentication.anonymousAuthentication.enabled:true"

            if (![string]::IsNullOrWhiteSpace($Domain)) {
                $_args += " /ftpServer.security.authentication.anonymousAuthentication.defaultLogonDomain:$($Domain)"
            }

            if (![string]::IsNullOrWhiteSpace($LogonMethod)) {
                $_args += " /ftpServer.security.authentication.anonymousAuthentication.logonMethod:$($LogonMethod)"
            }

            if ($null -ne $Credentials) {
                $info = Get-IISMCredentialDetails -Credentials $Credentials
                $_args += " /ftpServer.security.authentication.anonymousAuthentication.userName:$($info.Username) /ftpServer.security.authentication.anonymousAuthentication.password:$($info.Password)"
            }
        }

        'Basic' {
            $_args = "/ftpServer.security.authentication.basicAuthentication.enabled:true"

            if (![string]::IsNullOrWhiteSpace($Domain)) {
                $_args += " /ftpServer.security.authentication.basicAuthentication.defaultLogonDomain:$($Domain)"
            }

            if (![string]::IsNullOrWhiteSpace($LogonMethod)) {
                $_args += " /ftpServer.security.authentication.basicAuthentication.logonMethod:$($LogonMethod)"
            }
        }

        'ClientCertificate' {
            $_args = "/ftpServer.security.authentication.clientCertAuthentication.enabled:true"
        }

        'Custom' {
            $_args = "/`"ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)'].enabled:true`""
        }
    }

    # run the command
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' $($_args)" -NoParse | Out-Null
}

function Disable-IISMFtpSiteAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(ParameterSetName='Anonymous')]
        [switch]
        $Anonymous,

        [Parameter(ParameterSetName='Basic')]
        [switch]
        $Basic,

        [Parameter(ParameterSetName='ClientCertificate')]
        [switch]
        $ClientCertificate,

        [Parameter(ParameterSetName='Custom')]
        [switch]
        $Custom,

        [Parameter(Mandatory=$true, ParameterSetName='Custom')]
        [string]
        $ProviderName
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # error if the site isn't ftp
    if (!(Test-IISMSiteIsFtp -Name $Name)) {
        throw "Website '$($Name)' is not an FTP site"
    }

    # build the command for the auth type
    $_args = [string]::Empty

    switch ($PSCmdlet.ParameterSetName) {
        'Anonymous' {
            $_args = "/ftpServer.security.authentication.anonymousAuthentication.enabled:false"
        }

        'Basic' {
            $_args = "/ftpServer.security.authentication.basicAuthentication.enabled:false"
        }

        'ClientCertificate' {
            $_args = "/ftpServer.security.authentication.clientCertAuthentication.enabled:false"
        }

        'Custom' {
            $_args = "/`"ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)'].enabled:false`""
        }
    }

    # run the command
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' $($_args)" -NoParse | Out-Null
}

function Add-IISMFtpSiteCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $ProviderName,

        [switch]
        $Enable
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # error if the site isn't ftp
    if (!(Test-IISMSiteIsFtp -Name $Name)) {
        throw "Website '$($Name)' is not an FTP site"
    }

    # remove first, in case details are different
    Remove-IISMFtpSiteCustomAuthentication -Name $Name -ProviderName $ProviderName

    # either add it anew, or enable
    $_provider = ((Get-IISMSite -Name $Name).Ftp.Security.Authentication.Custom.Providers | Where-Object { $_.Name -ieq $ProviderName })

    if ($null -eq $_provider) {
        # build the command
        $_args = "/+`"ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)',enabled='$($Enable.IsPresent)']`""

        # run the command
        Invoke-IISMAppCommand -Arguments "set site '$($Name)' $($_args)" -NoParse | Out-Null
    }
    else {
        Enable-IISMFtpSiteAuthentication -Custom -Name $Name -ProviderName $ProviderName
    }
}

function Remove-IISMFtpSiteCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $ProviderName
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # error if the site isn't ftp
    if (!(Test-IISMSiteIsFtp -Name $Name)) {
        throw "Website '$($Name)' is not an FTP site"
    }

    # build the command
    $_args = "/-`"ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)']`""

    # run the command
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' $($_args)" -NoParse | Out-Null
}

function Set-IISMFtpSiteSslPolicy
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true, ParameterSetName='Certificate')]
        [string]
        $CertificateName,

        [Parameter(Mandatory=$true, ParameterSetName='Thumbprint')]
        [string]
        $Thumbprint,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Require')]
        [string]
        $Policy,

        [switch]
        $Use128Bit
    )

    # if cert name, get thumbprint
    if ($PSCmdlet.ParameterSetName -ieq 'Certificate') {
        $Thumbprint = Get-IISMCertificateThumbprint -CertificateName $CertificateName
    }

    # error if no thumbprint
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        throw "A valid Certificate Name or Thumbprint is required when configuring FTP SSL for '$($Name)'"
    }

    # build the command
    $_args = "/ftpServer.security.ssl.serverCertHash:$($Thumbprint) /ftpServer.security.ssl.serverCertStoreName:My"
    $_args += " /ftpServer.security.ssl.ssl128:$($Use128Bit.IsPresent)"
    $_args += " /ftpServer.security.ssl.controlChannelPolicy:Ssl$($Policy) /ftpServer.security.ssl.dataChannelPolicy:Ssl$($Policy)"

    # run the command
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' $($_args)" -NoParse | Out-Null
}

function Get-IISMFtpSiteLogging
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $logFields = Get-IISMFtpSiteLogFields -Name $Name
            $logPath = Get-IISMFtpSiteLogPath -Name $Name
            $logPeriod = Get-IISMFtpSiteLogPeriod -Name $Name
        }

        default {
            $logFields = Get-IISMFtpSiteLogFields -Default
            $logPath = Get-IISMFtpSiteLogPath -Default
            $logPeriod = Get-IISMFtpSiteLogPeriod -Default
        }
    }

    return (ConvertTo-IISMFtpSiteLoggingObject `
        -Fields $logFields `
        -Path $logPath `
        -Period $logPeriod)
}



function Get-IISMFtpSiteLogPeriod
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            if (!(Test-IISMSiteIsFtp -Name $Name)) {
                throw "Website '$($Name)' is not an FTP site"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $period = $result.SITE.site.ftpServer.logFile.period
            if ([string]::IsNullOrWhiteSpace($period)) {
                $period = Get-IISMSiteLogPeriod -Default
            }
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $period = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.ftpServer.logFile.period
            $period = (Protect-IISMValue $period 'Daily')
        }
    }

    return $period
}

function Set-IISMFtpSiteLogPeriod
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Hourly', 'Daily', 'Weekly', 'Monthly')]
        [string]
        $Period,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            if (!(Test-IISMSiteIsFtp -Name $Name)) {
                throw "Website '$($Name)' is not an FTP site"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].ftpServer.logFile.period:$($Period)`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"siteDefaults.ftpServer.logFile.period:$($Period)`"" -NoParse | Out-Null
        }
    }
}

function Get-IISMFtpSiteLogPath
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            if (!(Test-IISMSiteIsFtp -Name $Name)) {
                throw "Website '$($Name)' is not an FTP site"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $logpath = $result.SITE.site.ftpServer.logFile.directory
            if ([string]::IsNullOrWhiteSpace($logpath)) {
                $logpath = Get-IISMSiteLogPath -Default
            }

            $logpath = (Join-Path $logpath "FTPSVC$($result.SITE.site.id)")
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $logpath = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.ftpServer.logFile.directory
            $logpath = (Protect-IISMValue $logpath (Get-IISMSiteDefaultLogPath))
        }
    }

    return [System.Environment]::ExpandEnvironmentVariables($logpath)
}

function Set-IISMFtpSiteLogPath
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            if (!(Test-IISMSiteIsFtp -Name $Name)) {
                throw "Website '$($Name)' is not an FTP site"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].ftpServer.logFile.directory:$($Path)`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"siteDefaults.ftpServer.logFile.directory:$($Path)`"" -NoParse | Out-Null
        }
    }
}

function Get-IISMFtpSiteLogFields
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            if (!(Test-IISMSiteIsFtp -Name $Name)) {
                throw "Website '$($Name)' is not an FTP site"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $fields = $result.SITE.site.ftpServer.logFile.logExtFileFlags
            if ([string]::IsNullOrWhiteSpace($fields)) {
                $fields = Get-IISMFtpSiteLogFields -Default
            }
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $fields = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.ftpServer.logFile.logExtFileFlags
            $fields = (Protect-IISMValue $fields (Get-IISMFtpSiteDefaultLogFields))
        }
    }

    return ($fields -split ',').Trim()
}

function Set-IISMFtpSiteLogFields
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string[]]
        $Fields,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            if (!(Test-IISMSiteIsFtp -Name $Name)) {
                throw "Website '$($Name)' is not an FTP site"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].ftpServer.logFile.logExtFileFlags:$($Fields -join ',')`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"siteDefaults.ftpServer.logFile.logExtFileFlags:$($Fields -join ',')`"" -NoParse | Out-Null
        }
    }
}

function Add-IISMFtpSiteLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = Get-IISMFtpSiteLogFields -Name $Name
            if ($fields -inotcontains $Field) {
                $fields += $Field
            }

            Set-IISMFtpSiteLogFields -Name $Name -Fields $fields
        }

        default {
            $fields = Get-IISMFtpSiteLogFields -Default
            if ($fields -inotcontains $Field) {
                $fields += $Field
            }

            Set-IISMFtpSiteLogFields -Default -Fields $fields
        }
    }
}

function Remove-IISMFtpSiteLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = (Get-IISMFtpSiteLogFields -Name $Name | Where-Object { $_ -ine $Field })
            Set-IISMFtpSiteLogFields -Name $Name -Fields $fields
        }

        default {
            $fields = (Get-IISMFtpSiteLogFields -Default | Where-Object { $_ -ine $Field })
            Set-IISMFtpSiteLogFields -Default -Fields $fields
        }
    }
}

function Clear-IISMFtpSiteLogFields
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            Set-IISMFtpSiteLogFields -Name $Name -Fields @()
        }

        default {
            Set-IISMFtpSiteLogFields -Default -Fields @()
        }
    }
}

function Test-IISMFtpSiteLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    # get current fields
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = Get-IISMFtpSiteLogFields -Name $Name
        }

        default {
            $fields = Get-IISMFtpSiteLogFields -Default
        }
    }

    return ($fields -icontains $Field)
}