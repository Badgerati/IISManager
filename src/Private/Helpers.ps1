function Test-IsUnix
{
    return $PSVersionTable.Platform -ieq 'unix'
}

function Invoke-IISMNetshCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments,

        [switch]
        $NoError
    )

    $result = (Invoke-Expression -Command "$(Get-IISMNetshPath) $Arguments")

    if ($LASTEXITCODE -ne 0 -and !$NoError) {
        throw "Failed to run netsh: $($result)"
    }

    return $result
}

function Invoke-IISMNetCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments,

        [switch]
        $NoError
    )

    $result = (Invoke-Expression -Command "$(Get-IISMNetPath) $Arguments 2>&1")

    if ($LASTEXITCODE -ne 0 -and !$NoError) {
        throw "Failed to run net: $($result)"
    }

    return $result
}

function Invoke-IISMResetCommand
{
    param (
        [Parameter()]
        [string]
        $Arguments,

        [switch]
        $NoError
    )

    $result = (Invoke-Expression -Command "$(Get-IISMResetPath) $Arguments")

    if ($LASTEXITCODE -ne 0 -and !$NoError) {
        throw "Failed to run iisreset: $($result)"
    }

    return $result
}

function Get-IISMSiteBindingInformation
{
    param (
        [Parameter(Mandatory=$true)]
        $Binding
    )

    # get the protocol
    $protocol = $Binding.protocol
    $info = @{
        IP = $null
        Port = $null
        Hostname = $null
    }

    # get ip, port, hostname
    $split = ($Binding.bindingInformation -split ':')

    switch ($protocol.ToLowerInvariant()) {
        'net.tcp' {
            $info.Port = $split[0]
            $info.Hostname = $split[1]
        }

        { @('net.msmq', 'net.pipe', 'msmq.formatname') -icontains $_ } {
            $info.Hostname = $split[0]
        }

        default {
            $info.IP = $split[0]
            $info.Port = $split[1]
            $info.Hostname = $split[2]
        }
    }

    # get cert info for https
    $cert = $null
    if ($protocol -ieq 'https') {
        $cert = Get-IISMSiteBindingCertificate -Port $info.Port -IPAddress $info.IP -Hostname $info.Hostname
    }

    # set the binding info and return
    $info = @{
        Protocol = $protocol
        IPAddress = $info.IP
        Port = $info.Port
        Hostname = $info.Hostname
        Certificate = $cert
    }

    return $info
}

function Get-IISMBindingCommandString
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Protocol,

        [Parameter()]
        [int]
        $Port,

        [Parameter()]
        [string]
        $IPAddress,

        [Parameter()]
        [string]
        $Hostname
    )

    if ([string]::IsNullOrWhiteSpace($IPAddress) -and [string]::IsNullOrWhiteSpace($Hostname) -and $Port -le 0) {
        return "bindings.[protocol='$($Protocol)']"
    }

    $str = [string]::Empty

    switch ($Protocol.ToLowerInvariant()) {
        'net.tcp' {
            $str = "$($Port):$($Hostname)"
        }

        { @('net.msmq', 'net.pipe', 'msmq.formatname') -icontains $_ } {
            $str = "$($Hostname)"
        }

        default {
            $str = "$($IPAddress):$($Port):$($Hostname)"
        }
    }

    return "bindings.[protocol='$($Protocol)',bindingInformation='$($str)']"
}

function Get-IISMFtpAuthorizationCommandString
{
    param(
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
        $Role
    )

    return "[accessType='$($AccessType)',permissions='$($Permission -join ',')',roles='$($Role -join ',')',users='$($User -join ',')']"
}

function Get-IISMFtpIPSecurityCommandString
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [string]
        $IPAddress,

        [Parameter()]
        [string]
        $SubnetMask
    )

    $allowed = ($AccessType -ieq 'Allow')

    if ([string]::IsNullOrWhiteSpace($SubnetMask)) {
        $SubnetMask = '255.255.255.255'
    }

    return "[allowed='$($allowed)',subnetMask='$($SubnetMask)',ipAddress='$($IPAddress)']"
}

function Wait-IISMBackgroundTask
{
    param (
        [Parameter(Mandatory=$true)]
        [scriptblock]
        $ScriptBlock
    )

    foreach ($i in (0..10)) {
        $result = (. $ScriptBlock)
        if ($result) {
            return
        }

        Start-Sleep -Milliseconds 500
    }

    throw 'Resource not created in time'
}

function Add-IISMSlash
{
    param (
        [Parameter()]
        [string]
        $Value,

        [switch]
        $CheckNonEmpty,

        [switch]
        $Append
    )

    if ($CheckNonEmpty -and [string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    if ($Append) {
        if (!$Value.EndsWith('/')) {
            $Value = "$($Value)/"
        }
    }
    else {
        if (!$Value.StartsWith('/')) {
            $Value = "/$($Value)"
        }
    }

    return $Value
}

function Protect-IISMValue
{
    param (
        [Parameter()]
        $Value1,

        [Parameter()]
        $Value2
    )

    if (($null -eq $Value1) -or [string]::IsNullOrWhiteSpace($Value1)) {
        return $Value2
    }

    return $Value1
}

function Get-IISMCredentialDetails
{
    param(
        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credentials
    )

    $domain = $Credentials.GetNetworkCredential().Domain
    $username = $Credentials.GetNetworkCredential().UserName
    $password = $Credentials.GetNetworkCredential().Password

    if (![string]::IsNullOrWhiteSpace($domain)) {
        $username = "$($domain)\$($username)"
    }

    return @{
        Username = $username
        Password = $password
    }
}

function Split-IISMAppName
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $AppName
    )

    $atoms = @($AppName -split '/')

    $_siteName = $atoms[0]
    $_appName = '/'

    if ($atoms.Length -gt 1) {
        $_appName = ($atoms[1..($atoms.Length - 1)] -join '/')
    }

    return @{
        SiteName = $_siteName
        AppName = $_appName
    }
}

function Split-IISMDirectoryName
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $DirName
    )

    $atoms = @($DirName -split '/')

    $_siteName = $atoms[0]
    $_appName = '/'
    $_dirName = [string]::Empty

    # if name ends with a slash, it's a app
    if ($DirName.EndsWith('/')) {
        $atoms = $atoms[0..($atoms.Length - 2)]
        if ($atoms.Length -gt 1) {
            $_appName = ($atoms[1..($atoms.Length - 1)] -join '/')
        }
    }

    # else it's a vdir
    else {
        $_dirName = $atoms[$atoms.Length - 1]

        if ($atoms.Length -gt 2) {
            $_appName = ($atoms[1..($atoms.Length - 2)] -join '/')
        }
    }

    return @{
        SiteName = $_siteName
        AppName = $_appName
        DirName = $_dirName
    }
}

function Get-IISMDirectoryFtpAuthorizationInternal
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    # get the rules
    $result = Invoke-IISMAppCommand -Arguments "list config '$($Name)' /section:system.ftpServer/security/authorization"

    # just return if there are no results
    if ($null -eq $result.CONFIG) {
        return $null
    }

    return (ConvertTo-IISMFtpAuthorizationObject -Section $result.CONFIG.'system.ftpServer-security-authorization')
}

function Get-IISMDirectoryFtpIPSecurityInternal
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    # get the rules
    $result = Invoke-IISMAppCommand -Arguments "list config '$($Name)' /section:system.ftpServer/security/ipSecurity"

    # just return if there are no results
    if ($null -eq $result.CONFIG) {
        return $null
    }

    return (ConvertTo-IISMFtpIPSecurityObject -Section $result.CONFIG.'system.ftpServer-security-ipSecurity')
}