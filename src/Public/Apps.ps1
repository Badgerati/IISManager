function Get-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $SiteName,

        [Parameter()]
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

    if ($null -eq $result.APP) {
        return $null
    }

    $pools = Get-IISMAppPool
    $dirs = Get-IISMDirectory
    ConvertTo-IISMAppObject -Apps $result.APP -AppPools $pools -Directories $dirs
}

function Test-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $Name = '/'
    )

    return ($null -ne (Get-IISMApp -SiteName $SiteName -Name $Name))
}

function Remove-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $Name = '/'
    )

    $Name = Add-IISMSlash -Value $Name

    if (Test-IISMApp -SiteName $SiteName -Name $Name) {
        Invoke-IISMAppCommand -Arguments "delete app '$($SiteName)$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMApp)
}

function New-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $Name = '/',

        [Parameter(Mandatory=$true)]
        [string]
        $PhysicalPath,

        [Parameter()]
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
    return (Get-IISMApp -SiteName $SiteName -Name $Name)
}

function Update-IISMApp
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $Name = '/',

        [Parameter()]
        [string]
        $PhysicalPath,

        [Parameter()]
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
    return (Get-IISMApp -SiteName $SiteName -Name $Name)
}