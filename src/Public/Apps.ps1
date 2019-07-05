function Get-IISMApps
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('n')]
        [string]
        $Name
    )

    $Name = Add-IISMSlash -Value $Name
    $AppName = "$($SiteName)$($Name)"

    if (![string]::IsNullOrWhiteSpace($SiteName)) {
        $result = Invoke-IISMAppCommand -Arguments "list app '$($AppName)'" -NoError
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list apps' -NoError
    }

    if ($null -eq $result) {
        return $null
    }

    $pools = Get-IISMAppPools
    $dirs = Get-IISMDirectories
    ConvertTo-IISMAppObject -Apps $result.APP -AppPools $pools -Directories $dirs
}

function Test-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('n')]
        [string]
        $Name = '/'
    )

    return ($null -ne (Get-IISMApps -SiteName $SiteName -Name $Name))
}

function Remove-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('n')]
        [string]
        $Name = '/'
    )

    $Name = Add-IISMSlash -Value $Name

    if (Test-IISMApp -SiteName $SiteName -Name $Name) {
        Invoke-IISMAppCommand -Arguments "delete app '$($SiteName)$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMApps)
}

function New-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('n')]
        [string]
        $Name = '/',

        [Parameter(Mandatory=$true)]
        [Alias('p')]
        [string]
        $PhysicalPath,

        [Parameter()]
        [Alias('apn')]
        [string]
        $AppPoolName
    )

    $Name = Add-IISMSlash -Value $Name

    # error if app already exists
    if (Test-IISMApp -SiteName $SiteName -Name $Name) {
        throw "Application '$($SiteName)$($Name)' already exists in IIS"
    }

    # create the app
    $_args = "/site.name:'$($SiteName)' /path:$($Name) /physicalPath:'$($PhysicalPath)'"
    if (![string]::IsNullOrWhiteSpace($AppPoolName)) {
        $_args += " /applicationPool:'$($AppPoolName)'"
    }

    Invoke-IISMAppCommand -Arguments "add app $($_args)" -NoParse | Out-Null
    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMApp -SiteName $SiteName -Name $Name }

    # return the app
    return (Get-IISMApps -SiteName $SiteName -Name $Name)
}

function Update-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('n')]
        [string]
        $Name = '/',

        [Parameter()]
        [Alias('p')]
        [string]
        $PhysicalPath,

        [Parameter()]
        [Alias('apn')]
        [string]
        $AppPoolName
    )

    $Name = Add-IISMSlash -Value $Name
    $AppName = "$($SiteName)$($Name)"

    # error if app doesn't exists
    if (!(Test-IISMApp -SiteName $SiteName -Name $Name)) {
        throw "Application '$($AppName)' does not exist in IIS"
    }

    # update the physical path
    if (![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        Invoke-IISMAppCommand -Arguments "set app '$($AppName)' /physicalPath:'$($PhysicalPath)'" -NoParse | Out-Null
    }

    # update the application pool
    if (![string]::IsNullOrWhiteSpace($AppPoolName)) {
        Invoke-IISMAppCommand -Arguments "set app '$($AppName)' /applicationPool:'$($AppPoolName)'" -NoParse | Out-Null
    }

    # return the app
    return (Get-IISMApps -SiteName $SiteName -Name $Name)
}