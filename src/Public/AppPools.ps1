function Get-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list apppool '$($Name)'" -NoError
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list apppools' -NoError
    }

    if ($null -eq $result.APPPOOL) {
        return $null
    }

    return (ConvertTo-IISMAppPoolObject -AppPools $result.APPPOOL)
}

function Get-IISMAppPools
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $Names
    )

    return @(foreach ($name in $Names) { Get-IISMAppPool -Name $name })
}

function Test-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISMAppPool -Name $Name))
}

function Test-IISMAppPoolRunning
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ((Get-IISMAppPool -Name $Name).State -ieq 'started')
}

function Stop-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMAppPoolRunning -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "stop apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPool -Name $Name)
}

function Start-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (Test-IISMAppPoolRunning -Name $Name) {
        return
    }

    Invoke-IISMAppCommand -Arguments "start apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPool -Name $Name)
}

function Restart-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    Stop-IISMAppPool -Name $Name | Out-Null
    Start-IISMAppPool -Name $Name | Out-Null
    return (Get-IISMAppPool -Name $Name)
}

function Reset-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMAppPoolRunning -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "recycle apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPool -Name $Name)
}

function Remove-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMAppPool -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "delete apppool '$($Name)'" -NoParse | Out-Null
    return (Get-IISMAppPool)
}

function New-IISMAppPool
{
    [CmdletBinding()]
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

    # error if app-pool already exists
    if (Test-IISMAppPool -Name $Name) {
        throw "Application Pool '$($Name)' already exists in IIS"
    }

    # create the app-pool
    $_args = "/name:'$($Name)' /managedRuntimeVersion:v$($RuntimeVersion) /managedPipelineMode:$($PipelineMode) /enable32BitAppOnWin64:$($Enable32Bit)"
    Invoke-IISMAppCommand -Arguments "add apppool $($_args)" -NoParse | Out-Null
    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMAppPool -Name $Name }

    # return the app-pool
    return (Get-IISMAppPool -Name $Name)
}

function Update-IISMAppPool
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [ValidateSet('', '2.0', '4.0')]
        [string]
        $RuntimeVersion = '',

        [Parameter()]
        [ValidateSet('', 'Classic', 'Integrated')]
        [string]
        $PipelineMode = '',

        [Parameter()]
        [int]
        $QueueLength = 0
    )

    # error if the app-pool doesn't exist
    if (!(Test-IISMAppPool -Name $Name)) {
        throw "Application Pool '$($Name)' does not exist in IIS"
    }

    # update the runtime
    if (![string]::IsNullOrWhiteSpace($RuntimeVersion)) {
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /managedRuntimeVersion:v$($RuntimeVersion)" -NoParse | Out-Null
    }

    # update the pipeline mode
    if (![string]::IsNullOrWhiteSpace($PipelineMode)) {
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /managedPipelineMode:$($PipelineMode)" -NoParse | Out-Null
    }

    # update the queue length
    if ($QueueLength -gt 0) {
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /queueLength:$($QueueLength)" -NoParse | Out-Null
    }

    # return the app-pool
    return (Get-IISMAppPool -Name $Name)
}

function Update-IISMAppPoolProcessModel
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [ValidateSet('', 'ApplicationPoolIdentity', 'LocalService', 'LocalSystem', 'NetworkService', 'SpecificUser')]
        [string]
        $IdentifyType = '',

        [Parameter()]
        [pscredential]
        $Credentials,

        [Parameter()]
        [int]
        $IdleTimeOut = -1,

        [Parameter()]
        [ValidateSet('', 'Terminate', 'Suspend')]
        [string]
        $IdleTimeOutAction = '',

        [Parameter()]
        [int]
        $WorkerProcesses = -1
    )

    # error if the app-pool doesn't exist
    if (!(Test-IISMAppPool -Name $Name)) {
        throw "Application Pool '$($Name)' does not exist in IIS"
    }

    # set the idle timeout
    if ($IdleTimeOut -ge 0) {
        $strTimeout = [timespan]::FromMinutes($IdleTimeOut).ToString()
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /processModel.idleTimeout:$($strTimeout)" -NoParse | Out-Null
    }

    # set the idle timeout action
    if (![string]::IsNullOrWhiteSpace($IdleTimeOutAction)) {
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /processModel.idleTimeoutAction:$($IdleTimeOutAction)" -NoParse | Out-Null
    }

    # set the max worker processes
    if ($WorkerProcesses -ge 0) {
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /processModel.maxProcesses:$($WorkerProcesses)" -NoParse | Out-Null
    }

    # set the user identity
    if (![string]::IsNullOrWhiteSpace($IdentifyType)) {
        # setup as specific user with creds
        if ($IdentifyType -ieq 'SpecificUser') {
            if ($null -eq $Credentials) {
                throw "No credentials supplied when attempting to set the '$($Name)' application pool to run as SpecificUser"
            }

            $domain = $Credentials.GetNetworkCredential().Domain
            $username = $Credentials.GetNetworkCredential().UserName
            $password = $Credentials.GetNetworkCredential().Password

            if (![string]::IsNullOrWhiteSpace($domain)) {
                $username = "$($domain)\$($username)"
            }

            $_args = "/processModel.identityType:$($IdentifyType) /processModel.userName:$($username) /processModel.password:$($password)"
            Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' $($_args)" -NoParse | Out-Null
        }

        # setup as inbuilt identity
        else {
            Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /processModel.identityType:$($IdentifyType)" -NoParse | Out-Null
        }
    }

    # return the app-pool
    return (Get-IISMAppPool -Name $Name)
}

function Update-IISMAppPoolRecycling
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter()]
        [int]
        $RecycleInterval = -1,

        [Parameter()]
        [timespan[]]
        $RecycleTimes = $null
    )

    # error if the app-pool doesn't exist
    if (!(Test-IISMAppPool -Name $Name)) {
        throw "Application Pool '$($Name)' does not exist in IIS"
    }

    # set a recycle interval
    if ($RecycleInterval -ge 0) {
        $strInterval = [timespan]::FromMinutes($RecycleInterval).ToString()
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /recycling.periodicRestart.time:$($strInterval)" -NoParse | Out-Null
    }

    # set recycling times
    if (($RecycleTimes | Measure-Object).Count -gt 0) {
        # remove all current times
        Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /-recycling.periodicRestart.schedule" -NoParse | Out-Null

        # add the new times
        foreach ($time in @($RecycleTimes)) {
            Invoke-IISMAppCommand -Arguments "set apppool '$($Name)' /+`"recycling.periodicRestart.schedule.[value='$($time.ToString())']`"" -NoParse | Out-Null
        }
    }

    # return the app-pool
    return (Get-IISMAppPool -Name $Name)
}
