function Get-IISSites
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISAppCommand -Arguments "list site '$($Name)'"
    }
    else {
        $result = Invoke-IISAppCommand -Arguments 'list sites'
    }

    if ($null -eq $result) {
        return $null
    }

    $apps = Get-IISApps
    ConvertTo-IISSiteObject -Sites $result.SITE -Apps $apps
}

function Test-IISSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISSites -Name $Name))
}

function Test-IISSiteRunning
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ((Get-IISSites -Name $Name).State -ieq 'started')
}

function Stop-IISSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISSiteRunning -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "stop site '$($Name)'" -NoParse | Out-Null
}

function Start-IISSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISSiteRunning -Name $Name) {
        return
    }

    Invoke-IISAppCommand -Arguments "start site '$($Name)'" -NoParse | Out-Null
}

function Restart-IISSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )
    
    Stop-IISSite -Name $Name
    Start-IISSite -Name $Name
}

function Get-IISSiteBindings
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return (Get-IISSites -Name $Name).Bindings
}

function Get-IISSitePhysicalPath
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $App = '/'
    )

    return (Get-IISSites -Name $Name).Apps[$App].Directory.PhysicalPath
}

function Remove-IISSite
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISSite -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "delete site '$($Name)'" -NoParse | Out-Null
}