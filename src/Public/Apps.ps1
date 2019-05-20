function Get-IISApps
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISAppCommand -Arguments "list app '$($Name)'"
    }
    else {
        $result = Invoke-IISAppCommand -Arguments 'list apps'
    }

    if ($null -eq $result) {
        return $null
    }

    $pools = Get-IISAppPools
    $dirs = Get-IISDirectories
    ConvertTo-IISAppObject -Apps $result.APP -AppPools $pools -Directories $dirs
}

function Test-IISApp
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISApps -Name $Name))
}

function Remove-IISApp
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISApp -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "delete app '$($Name)'" -NoParse | Out-Null
    return (Get-IISApps)
}

#TODO: create app?
#TODO: modify app?