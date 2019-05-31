function Get-IISMSites
{
    param (
        [Parameter()]
        [string]
        $Name,

        [Parameter()]
        [string]
        $PhysicalPath
    )

    # get either one site, or all sites
    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list site '$($Name)'"
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list sites'
    }

    # just return if there are no results
    if ($null -eq $result) {
        return $null
    }

    # get list of IIS apps to map to sites
    $apps = Get-IISMApps
    $sites = ConvertTo-IISMSiteObject -Sites $result.SITE -Apps $apps

    # if we have a physical path, filter sites
    if (![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        $sites = @($sites | Where-Object { $_.Apps | Where-Object { $_.Directory.PhysicalPath -ieq $PhysicalPath } })
        foreach ($site in $sites) {
            $site.Apps = @($site.Apps | Where-Object { $_.Directory.PhysicalPath -ieq $PhysicalPath })
        }
    }

    return $sites
}

function Test-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISMSites -Name $Name))
}

function Test-IISMSiteRunning
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ((Get-IISMSites -Name $Name).State -ieq 'started')
}

function Stop-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMSiteRunning -Name $Name) {
        Invoke-IISMAppCommand -Arguments "stop site '$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMSites -Name $Name)
}

function Start-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMSiteRunning -Name $Name)) {
        Invoke-IISMAppCommand -Arguments "start site '$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMSites -Name $Name)
}

function Restart-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )
    
    Stop-IISMSite -Name $Name | Out-Null
    Start-IISMSite -Name $Name | Out-Null
    return (Get-IISMSites -Name $Name)
}

function Get-IISMSiteBindings
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return (Get-IISMSites -Name $Name).Bindings
}

function Get-IISMSitePhysicalPath
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppName = '/'
    )

    $AppName = Add-IISMSlash -Value $AppName

    return ((Get-IISMSites -Name $Name).Apps | Where-Object {
        $_.Path -ieq $AppName
    } | Select-Object -First 1).Directory.PhysicalPath
}

function Edit-IISMSitePhysicalPath
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter(Mandatory=$true)]
        [string]
        $PhysicalPath
    )

    $AppName = Add-IISMSlash -Value $AppName

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    # get the site info
    $site = Get-IISMSites -Name $Name

    # error if this site doesn't have the supplied app
    $app = ($site.Apps | Where-Object { $_.Path -ieq $AppName })
    if ($null -eq $app) {
        throw "The app '$($AppName)' does not exist against the website '$($Name)' in IIS"
    }

    # update the physical path
    Update-IISMDirectory -SiteName $Name -AppName $AppName -PhysicalPath $PhysicalPath | Out-Null

    # return the site
    return (Get-IISMSites -Name $Name)
}

function Remove-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMSite -Name $Name) {
        Invoke-IISMAppCommand -Arguments "delete site '$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMSites)
}

function Remove-IISMSiteBinding
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
        $Hostname
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    $binding = Get-IISMBindingCommandString -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /-`"$($binding)`"" -NoParse | Out-Null
    return (Get-IISMSiteBindings -Name $Name)
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
        $Hostname
    )

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $Name)) {
        throw "Website '$($Name)' does not exist in IIS"
    }

    $binding = Get-IISMBindingCommandString -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /+`"$($binding)`"" -NoParse | Out-Null
    return (Get-IISMSiteBindings -Name $Name)
}

function Edit-IISMSiteAppPool
{
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
    return (Get-IISMSites -Name $Name)
}

function New-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $AppPoolName,

        [Parameter(Mandatory=$true)]
        [string]
        $PhysicalPath,

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

    # if no app-pool name, set to the site name
    if ([string]::IsNullOrWhiteSpace($AppPoolName)) {
        $AppPoolName = $Name
    }

    # error if site already exists
    if (Test-IISMSite -Name $Name) {
        throw "Website '$($Name)' already exists in IIS"
    }

    # if the app-pool doesn't exist, create a default one
    if (!(Test-IISMAppPool -Name $AppPoolName)) {
        New-IISMAppPool -Name $AppPoolName | Out-Null
    }

    # create the site in IIS
    $_args = "/name:'$($Name)' /physicalPath:'$($PhysicalPath)' /bindings:$($Protocol)/$($IPAddress):$($Port):$($Hostname)"
    Invoke-IISMAppCommand -Arguments "add site $($_args)" -NoParse | Out-Null

    # bind the app-pool to the site's default app
    Update-IISMSiteAppPool -Name $Name -App '/' -AppPoolName $AppPoolName | Out-Null
    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMSite -Name $Name }

    # if https, bind a certificate if thumbprint supplied
    if ($Protocol -ieq 'https' -and ![string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        Set-IISMSiteBindingCertificate -CertificateThumbprint $CertificateThumbprint -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    }

    # return the site
    return (Get-IISMSites -Name $Name)
}

function Set-IISMSiteBindingCertificate
{
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
    if (![string]::IsNullOrWhiteSpace($Hostname)) {
        $addr = "$($Hostname):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http add sslcert hostnameport=$($addr) certhash=$($CertificateThumbprint) certstorename=MY appid='$($appId)'")
    }

    # else, bind using IP address
    else {
        $addr = "$($IPAddress):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http add sslcert ipport=$($addr) certhash=$($CertificateThumbprint) appid='$($appId)'")
    }

    if ($LASTEXITCODE -ne 0 -or !$?) {
        throw "Failed to bind certificate against '$($addr)':`n$($result)"
    }
}

function Remove-IISMSiteBindingCertificate
{
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
    if (![string]::IsNullOrWhiteSpace($Hostname)) {
        $addr = "$($Hostname):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http delete sslcert hostnameport=$($addr)")
    }

    # else, delete using IP address
    else {
        $addr = "$($IPAddress):$($Port)"
        $result = (Invoke-IISMNetshCommand -Arguments "http add sslcert ipport=$($addr)")
    }

    if ($LASTEXITCODE -ne 0 -or !$?) {
        throw "Failed to delete certificate against '$($addr)':`n$($result)"
    }
}

function Test-IISMSiteBindingCertificate
{
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

    # get netsh details by ip address
    $details = (Invoke-IISMNetshCommand -Arguments "http show sslcert ipport=$($IPAddress):$($Port)")

    # if that threw an error, and we have a hostname, check that
    if ($LASTEXITCODE -ne 0 -and ![string]::IsNullOrWhiteSpace($Hostname)) {
        $details = (Invoke-IISMNetshCommand -Arguments "http show sslcert hostnameport=$($Hostname):$($Port)")
    }

    # get the thumbprint from the output
    $thumbprint = (($details -imatch 'Certificate Hash\s+:\s+([a-z0-9]+)') -split ':')[1].Trim()

    # if no thumbprint, return null
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        return $null
    }

    # get cert subject if on windows
    if (!(Test-IsUnix)) {
        $subject = (Get-ChildItem "Cert:/LocalMachine/My/$($t)").Subject
    }

    # return the cert details
    return (New-Object -TypeName psobject |
        Add-Member -MemberType NoteProperty -Name Thumbprint -Value $thumbprint -PassThru |
        Add-Member -MemberType NoteProperty -Name Subject -Value $subject -PassThru)
}