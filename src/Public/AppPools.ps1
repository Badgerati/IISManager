function Get-IISMAppPools
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list apppool '$($Name)'"
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list apppools'
    }

    if ($null -eq $result) {
        return $null
    }

    ConvertTo-IISMAppPoolObject -AppPools $result.APPPOOL
}

function Test-IISMAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISMAppPools -Name $Name))
}

function Test-IISMAppPoolRunning
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ((Get-IISMAppPools -Name $Name).State -ieq 'started')
}

function Stop-IISMAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMAppPoolRunning -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "stop apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPools -Name $Name)
}

function Start-IISMAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMAppPoolRunning -Name $Name) {
        return
    }

    Invoke-IISMAppCommand -Arguments "start apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPools -Name $Name)
}

function Restart-IISMAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )
    
    Stop-IISMAppPool -Name $Name | Out-Null
    Start-IISMAppPool -Name $Name | Out-Null
    return (Get-IISMAppPools -Name $Name)
}

function Reset-IISMAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMAppPoolRunning -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "recycle apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPools -Name $Name)
}

function Remove-IISMAppPool
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMAppPool -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "delete apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPools)
}

function New-IISMAppPool
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

    if (Test-IISMAppPool -Name $Name) {
        Write-IISMWarning "The application pool already exists"
        return
    }

    $_args = "/name:'$($Name)' /managedRuntimeVersion:v$($RuntimeVersion) /managedPipelineMode:$($PipelineMode) /enable32BitAppOnWin64:$($Enable32Bit)"
    Invoke-IISMAppCommand -Arguments "add apppool $($_args)" -NoParse | Out-Null

    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMAppPool -Name $Name }
    return (Get-IISMAppPools -Name $Name)
}

#TODO: modify app pool