function Get-IISMSites
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list site '$($Name)'"
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list sites'
    }

    if ($null -eq $result) {
        return $null
    }

    $apps = Get-IISMApps
    ConvertTo-IISMSiteObject -Sites $result.SITE -Apps $apps
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

    if (!(Test-IISMSiteRunning -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "stop site '$($Name)'" -NoParse | Out-Null
    return (Get-IISMSites -Name $Name)
}

function Start-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMSiteRunning -Name $Name) {
        return
    }

    Invoke-IISMAppCommand -Arguments "start site '$($Name)'" -NoParse | Out-Null
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
        $App = '/'
    )

    return (Get-IISMSites -Name $Name).Apps[$App].Directory.PhysicalPath
}

function Remove-IISMSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMSite -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "delete site '$($Name)'" -NoParse | Out-Null
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

    $binding = Get-IISMBindingCommandString -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /-$($binding)" -NoParse | Out-Null
    return (Get-IISMSiteBindings -Name $Name)
}

function New-IISMSiteBinding
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

    $binding = Get-IISMBindingCommandString -Protocol $Protocol -Port $Port -IPAddress $IPAddress -Hostname $Hostname
    Invoke-IISMAppCommand -Arguments "set site '$($Name)' /+$($binding)" -NoParse | Out-Null
    return (Get-IISMSiteBindings -Name $Name)
}

#TODO: create site
#TODO: modify site