function Get-IISMSite
{
    [CmdletBinding(DefaultParameterSetName='Path')]
    param (
        [Parameter()]
        [string]
        $Name,

        [Parameter(ParameterSetName='Path')]
        [string]
        $PhysicalPath,

        [Parameter(ParameterSetName='Quick')]
        [switch]
        $Quick
    )

    # get site(s)
    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list site '$($Name)'" -NoError
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list sites' -NoError
    }

    if ($null -eq $result.SITE) {
        return $null
    }

    # get list of IIS apps to map to sites
    $sites = ConvertTo-IISMSiteObject -Sites $result.SITE -Quick:$Quick

    # if we have a physical path, filter sites
    if (!$Quick -and ![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        $sites = @($sites | Where-Object {
            $_.Apps | Where-Object {
                $_.Directories | Where-Object {
                    $_.PhysicalPath -ieq $PhysicalPath
                }
            }
        })

        foreach ($site in $sites) {
            $site.Apps = @($site.Apps | Where-Object {
                $_.Directories | Where-Object {
                    $_.PhysicalPath -ieq $PhysicalPath
                }
            })
        }
    }

    return $sites
}

function Get-IISMSites
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $Names,

        [switch]
        $Quick
    )

    return @(foreach ($name in $Names) { Get-IISMSite -Name $name -Quick:$Quick })
}

function Test-IISMSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    $result = Invoke-IISMAppCommand -Arguments "list site '$($Name)'" -NoError
    return ($null -ne $result.SITE)
}

function Test-IISMSiteRunning
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ((Get-IISMSite -Name $Name -Quick).State -ieq 'started')
}

function Stop-IISMSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMSiteRunning -Name $Name) {
        Invoke-IISMAppCommand -Arguments "stop site '$($Name)'" -NoParse | Out-Null
        Invoke-IISMAppCommand -Arguments "set site '$($Name)' /serverAutoStart:false" -NoParse | Out-Null
    }

    return (Get-IISMSite -Name $Name -Quick)
}

function Start-IISMSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMSiteRunning -Name $Name)) {
        Invoke-IISMAppCommand -Arguments "start site '$($Name)'" -NoParse | Out-Null
        Invoke-IISMAppCommand -Arguments "set site '$($Name)' /serverAutoStart:true" -NoParse | Out-Null
    }

    return (Get-IISMSite -Name $Name -Quick)
}

function Restart-IISMSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )
    
    Stop-IISMSite -Name $Name | Out-Null
    Start-IISMSite -Name $Name | Out-Null
    return (Get-IISMSite -Name $Name -Quick)
}

function Get-IISMSiteBindings
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    # get site
    $result = Invoke-IISMAppCommand -Arguments "list site '$($Name)'" -NoError
    if ($null -eq $result.SITE) {
        return $null
    }

    # parse the list of binding
    return @(ConvertTo-IISMBindingObject -Site $result.SITE)
}

function Get-IISMSitePhysicalPath
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    $AppName = Add-IISMSlash -Value $AppName
    $DirName = Add-IISMSlash -Value $DirName

    $dirs = ((Get-IISMSite -Name $Name).Apps | Where-Object {
        $_.Path -ieq $AppName
    } | Select-Object -First 1).Directories
    
    return ($dirs | Where-Object {
        $_.Path -ieq $DirName
    } | Select-Object -First 1).PhysicalPath
}

function Get-IISMSiteAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppName = '/'
    )

    $AppName = Add-IISMSlash -Value $AppName

    return ((Get-IISMSite -Name $Name).Apps | Where-Object {
        $_.Path -ieq $AppName
    } | Select-Object -First 1).AppPool.Name
}

function Reset-IISMSiteAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    (Get-IISMSite -Name $Name).Apps.AppPool.Name | Sort-Object -Unique | ForEach-Object {
        Reset-IISMAppPool -Name $_ | Out-Null
    }
}

function Edit-IISMSitePhysicalPath
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter(Mandatory=$true)]
        [string]
        $PhysicalPath,

        [switch]
        $CreatePath
    )

    $AppName = Add-IISMSlash -Value $AppName

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # get the site info
    $site = Get-IISMSite -Name $Name

    # error if this site doesn't have the supplied app
    $app = ($site.Apps | Where-Object { $_.Path -ieq $AppName })
    if ($null -eq $app) {
        throw "The app '$($AppName)' does not exist against the website '$($Name)' in IIS"
    }

    # if create flag passed, make the path
    if ($CreatePath -and !(Test-Path $PhysicalPath)) {
        New-Item -Path $PhysicalPath -ItemType Directory -Force | Out-Null
    }

    # update the physical path
    Update-IISMDirectory -SiteName $Name -AppName $AppName -PhysicalPath $PhysicalPath | Out-Null

    # return the site
    return (Get-IISMSite -Name $Name)
}

function Remove-IISMSite
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMSite -Name $Name) {
        # first remove all bindings - in an attempt to remove cert bindings
        Remove-IISMSiteBindings -Name $Name

        # then, remove the site and everything else
        Invoke-IISMAppCommand -Arguments "delete site '$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMSite)
}

function Test-IISMSiteBinding
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet('ftp', 'http', 'https', 'msmq.formatname', 'net.msmq', 'net.pipe', 'net.tcp')]
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

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # get the website bindings
    $bindings = Get-IISMSiteBindings -Name $Name
    foreach ($b in $bindings) {
        if ($b.Protocol -ieq $Protocol -and $b.Port -eq $Port -and $b.IPAddress -ieq $IPAddress -and $b.Hostname -ieq $Hostname) {
            return $true
        }
    }

    return $false
}

function Remove-IISMSiteBindings
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # remove all bindings
    @(Get-IISMSiteBindings -Name $Name) | ForEach-Object {
        Remove-IISMSiteBinding -Name $Name -Protocol $_.Protocol -Port $_.Port -IPAddress $_.IPAddress -Hostname $_.Hostname | Out-Null
    }
}

function Remove-IISMSiteBinding
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet('ftp', 'http', 'https', 'msmq.formatname', 'net.msmq', 'net.pipe', 'net.tcp')]
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

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # do nothing if binding doesn't exist
    if (!(Test-IISMSiteBinding -Name $Name -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname)) {
        return
    }

    # if https, attempt to unbind cert first
    if ($Protocol -ieq 'https') {
        Remove-IISMSiteBindingCertificate -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    }

    $binding = Get-IISMBindingCommandString -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /-`"$($binding)`"" -NoParse | Out-Null
    return (Get-IISMSiteBindings -Name $Name)
}

function Remove-IISMSiteDefaultBinding
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return (Remove-IISMSiteBinding -Name $Name -Protocol http -Port 80 -IPAddress '*')
}

function Add-IISMSiteBinding
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet('ftp', 'http', 'https', 'msmq.formatname', 'net.msmq', 'net.pipe', 'net.tcp')]
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
        $Hostname,

        [Parameter()]
        [string]
        $CertificateThumbprint
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # attempt to remove the binding first, if it exists
    Remove-IISMSiteBinding -Name $Name -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname | Out-Null

    # add the binding
    $binding = Get-IISMBindingCommandString -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /+`"$($binding)`"" -NoParse | Out-Null

    # if https, bind a certificate if thumbprint supplied
    if ($Protocol -ieq 'https' -and ![string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        Set-IISMSiteBindingCertificate -CertificateThumbprint $CertificateThumbprint -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    }

    return (Get-IISMSiteBindings -Name $Name)
}

function Edit-IISMSiteAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppName ='/',

        [Parameter(Mandatory=$true)]
        [string]
        $AppPoolName
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # error if the app doesn't exist
    $AppName = Add-IISMSlash -Value $AppName
    $FullAppName = "$($Name)$($AppName)"

    if (!(Test-IISMApp -SiteName $Name -Name $AppName)) {
        throw "Application '$($FullAppName)' does not exist in IIS"
    }

    # if the app-pool doesn't exist, create a default one
    if (!(Test-IISMAppPool -Name $AppPoolName)) {
        New-IISMAppPool -Name $AppPoolName | Out-Null
    }

    # bind the app-pool to the site's app
    Invoke-IISMAppCommand -Arguments "set app '$($FullAppName)' /applicationPool:'$($AppPoolName)'" -NoParse | Out-Null

    # return the site
    return (Get-IISMSite -Name $Name)
}

function New-IISMSite
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppPoolName = 'DefaultAppPool',

        [Parameter(Mandatory=$true)]
        [string]
        $PhysicalPath,

        [Parameter()]
        [pscredential]
        $Credentials,

        [switch]
        $CreatePath,

        [switch]
        $DisableAutoStart
    )

    # error if site already exists
    if (Test-IISMSite -Name $Name) {
        throw "Website '$($Name)' already exists in IIS"
    }

    # if the app-pool doesn't exist, create a default one
    if (!(Test-IISMAppPool -Name $AppPoolName)) {
        New-IISMAppPool -Name $AppPoolName | Out-Null
    }

    # if create flag passed, make the path
    if ($CreatePath -and !(Test-Path $PhysicalPath)) {
        New-Item -Path $PhysicalPath -ItemType Directory -Force | Out-Null
    }

    # create the site in IIS
    $_args = "/name:'$($Name)' /physicalPath:'$($PhysicalPath)'"
    Invoke-IISMAppCommand -Arguments "add site $($_args)" -NoParse | Out-Null

    # set the physical vdir path creds
    if ($null -ne $Credentials) {
        Set-IISMDirectoryCredentials -SiteName $Name -Credentials $Credentials
    }

    # flag the site's auto start mode
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /serverAutoStart:$(!$DisableAutoStart)" -NoParse | Out-Null

    # bind the app-pool to the site's default app
    if ($AppPoolName -ine 'DefaultAppPool') {
        Edit-IISMSiteAppPool -Name $Name -AppName '/' -AppPoolName $AppPoolName | Out-Null
    }

    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMSite -Name $Name }

    # return the site
    return (Get-IISMSite -Name $Name)
}

function Set-IISMSiteBindingCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true)]
        [int]
        $Port,

        [Parameter()]
        [string]
        $IPAddress,

        [Parameter()]
        [string]
        $Hostname
    )

    # error if no ip/hostname
    if ([string]::IsNullOrWhiteSpace($Hostname) -and [string]::IsNullOrWhiteSpace($IPAddress)) {
        throw "A Hostname or an IP Address is required when binding a certificate"
    }

    # error if already bound with cert
    if (Test-IISMSiteBindingCertificate -Port $Port -IPAddress $IPAddress -Hostname $Hostname) {
        throw "The binding '$($IPAddress):$($Port):$($Hostname)' is already bound with a certificate"
    }

    $appId = '{a3ba417c-dc1d-446b-95a5-a306ab26c1af}'

    # bind cert using hostname
    if (![string]::IsNullOrWhiteSpace($Hostname) -and $Hostname -ine '*') {
        $addr = "$($Hostname):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http add sslcert hostnameport=$($addr) certhash=$($CertificateThumbprint) certstorename=MY appid='$($appId)'" -NoError)
    }

    # else, bind using IP address
    else {
        $addr = "$($IPAddress):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http add sslcert ipport=$($addr) certhash=$($CertificateThumbprint) appid='$($appId)'" -NoError)
    }

    if ($LASTEXITCODE -ne 0 -or !$?) {
        throw "Failed to bind certificate against '$($addr)':`n$($result)"
    }
}

function Remove-IISMSiteBindingCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [int]
        $Port,

        [Parameter()]
        [string]
        $IPAddress,

        [Parameter()]
        [string]
        $Hostname
    )

    # error if no ip/hostname
    if ([string]::IsNullOrWhiteSpace($Hostname) -and [string]::IsNullOrWhiteSpace($IPAddress)) {
        throw "A Hostname or an IP Address is required when removing a bound certificate"
    }

    # do nothing if not bound
    if (!(Test-IISMSiteBindingCertificate -Port $Port -IPAddress $IPAddress -Hostname $Hostname)) {
        return
    }

    # delete cert using hostname
    if (![string]::IsNullOrWhiteSpace($Hostname) -and $Hostname -ine '*') {
        $addr = "$($Hostname):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http delete sslcert hostnameport=$($addr)" -NoError)
    }

    # else, delete using IP address
    else {
        $addr = "$($IPAddress):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http delete sslcert ipport=$($addr)" -NoError)
    }

    if ($LASTEXITCODE -ne 0 -or !$?) {
        throw "Failed to delete certificate against '$($addr)':`n$($result)"
    }
}

function Test-IISMSiteBindingCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [int]
        $Port,

        [Parameter()]
        [string]
        $IPAddress,

        [Parameter()]
        [string]
        $Hostname
    )

    return ($null -ne (Get-IISMSiteBindingCertificate -Port $Port -IPAddress $IPAddress -Hostname $Hostname))
}

function Get-IISMSiteBindingCertificate
{
    [CmdletBinding(DefaultParameterSetName='Port')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Port')]
        [int]
        $Port,

        [Parameter(ParameterSetName='Port')]
        [string]
        $IPAddress,

        [Parameter(ParameterSetName='Port')]
        [string]
        $Hostname,

        [Parameter(Mandatory=$true, ParameterSetName='Thumbprint')]
        [string]
        $Thumbprint
    )

    if ($PSCmdlet.ParameterSetName -ieq 'port') {
        # get netsh details by ip address
        $details = (Invoke-IISMNetshCommand -Arguments "http show sslcert ipport=$($IPAddress):$($Port)" -NoError)

        # if that threw an error, and we have a hostname, check that
        if ($LASTEXITCODE -ne 0 -and ![string]::IsNullOrWhiteSpace($Hostname) -and $Hostname -ine '*') {
            $details = (Invoke-IISMNetshCommand -Arguments "http show sslcert hostnameport=$($Hostname):$($Port)" -NoError)
        }

        # get the thumbprint from the output
        $Thumbprint = (($details -imatch 'Certificate Hash\s+:\s+([a-z0-9]+)') -split ':')[1]
        if (![string]::IsNullOrWhiteSpace($Thumbprint)) {
            $Thumbprint = $Thumbprint.Trim()
        }
    }

    # if no thumbprint, return null
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return $null
    }

    # get cert subject if on windows
    if (!(Test-IsUnix)) {
        $subject = (Get-ChildItem "Cert:/LocalMachine/My/$($Thumbprint)").Subject
    }

    # return the cert details
    return @{
        Thumbprint = $Thumbprint
        Subject = $subject
    }
}

function Test-IISMSiteIsFtp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    $bindings = @(Get-IISMSiteBindings -Name $Name)
    return ($bindings.Protocol -icontains 'ftp')
}