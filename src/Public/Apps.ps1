function Get-IISMApps
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list app '$($Name)'"
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list apps'
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
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISMApps -Name $Name))
}

function Remove-IISMApp
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMApp -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "delete app '$($Name)'" -NoParse | Out-Null
    return (Get-IISMApps)
}

#TODO: create app?
#TODO: modify app?