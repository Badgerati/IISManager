function Get-IISAppPools
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISAppCommand -Arguments "list apppool '$($Name)'"
    }
    else {
        $result = Invoke-IISAppCommand -Arguments 'list apppools'
    }

    if ($null -eq $result) {
        return $null
    }

    ConvertTo-IISAppPoolObject -AppPools $result.APPPOOL
}

function Test-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISAppPools -Name $Name))
}

function Test-IISAppPoolRunning
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ((Get-IISAppPools -Name $Name).State -ieq 'started')
}

function Stop-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISAppPoolRunning -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "stop apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISAppPools -Name $Name)
}

function Start-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISAppPoolRunning -Name $Name) {
        return
    }

    Invoke-IISAppCommand -Arguments "start apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISAppPools -Name $Name)
}

function Restart-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )
    
    Stop-IISAppPool -Name $Name | Out-Null
    Start-IISAppPool -Name $Name | Out-Null
    return (Get-IISAppPools -Name $Name)
}

function Reset-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISAppPoolRunning -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "recycle apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISAppPools -Name $Name)
}

function Remove-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISAppPool -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "delete apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISAppPools)
}

function New-IISAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [ValidateSet('2.0', '4.0')]
        [string]
        $RuntimeVersion = '4.0',

        [Parameter()]
        [ValidateSet('Classic', 'Integrated')]
        [string]
        $PipelineMode = 'Integrated',

        [switch]
        $Enable32Bit
    )

    if (Test-IISAppPool -Name $Name) {
        Write-IISWarning "The application pool already exists"
        return
    }

    $_args = "/name:'$($Name)' /managedRuntimeVersion:v$($RuntimeVersion) /managedPipelineMode:$($PipelineMode) /enable32BitAppOnWin64:$($Enable32Bit)"
    Invoke-IISAppCommand -Arguments "add apppool $($_args)" -NoParse | Out-Null

    Wait-IISBackgroundTask -ScriptBlock { Test-IISAppPool -Name $Name }
    return (Get-IISAppPools -Name $Name)
}

#TODO: modify app pool