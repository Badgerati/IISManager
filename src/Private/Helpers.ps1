function Write-IISMWarning
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Message
    )

    Write-Host $Message -ForegroundColor Yellow
}

function Test-IsUnix
{
    return $PSVersionTable.Platform -ieq 'unix'
}

function Invoke-IISMAppCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments,

        [switch]
        $NoParse
    )

    if ($NoParse) {
        return (Invoke-Expression -Command "$(Get-IISMAppCmdPath) $Arguments")
    }
    else {
        return ([xml](Invoke-Expression -Command "$(Get-IISMAppCmdPath) $Arguments /xml /config")).appcmd
    }
}

function Invoke-IISMNetshCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments
    )

    return (Invoke-Expression -Command "$(Get-IISMNetshPath) $Arguments")
}

function Invoke-IISMNetCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments
    )

    return (Invoke-Expression -Command "$(Get-IISMNetPath) $Arguments")
}

function Get-IISMSiteBindingInformation
{
    param (
        [Parameter(Mandatory=$true)]
        $Binding
    )

    # get the protocol
    $protocol = $Binding.protocol
    $info = @{
        'IP' = $null;
        'Port' = $null;
        'Hostname' = $null
    }

    # get ip, port, hostname
    $split = ($Binding.bindingInformation -split ':')

    switch ($protocol.ToLowerInvariant()) {
        'net.tcp' {
            $info.Port = $split[0]
            $info.Hostname = $split[1]
        }

        { @('net.msmq', 'net.pipe', 'msmq.formatname') -icontains $_ } {
            $info.Hostname = $split[0]
        }

        default {
            $info.IP = $split[0]
            $info.Port = $split[1]
            $info.Hostname = $split[2]
        }
    }

    # get cert info for https
    $cert = $null
    if ($protocol -ieq 'https') {
        $cert = Get-IISMSiteBindingCertificate -Port $info.Port -IPAddress $info.IP -Hostname $info.Hostname
    }

    # set the binding info and return
    $info = (New-Object -TypeName psobject |
        Add-Member -MemberType NoteProperty -Name Protocol -Value $protocol -PassThru |
        Add-Member -MemberType NoteProperty -Name IPAddress -Value $info.IP -PassThru |
        Add-Member -MemberType NoteProperty -Name Port -Value $info.Port -PassThru |
        Add-Member -MemberType NoteProperty -Name Hostname -Value $info.Hostname -PassThru |
        Add-Member -MemberType NoteProperty -Name Certificate -Value $cert -PassThru)

    return $info
}

function Get-IISMBindingCommandString
{
    param (
        [Parameter(Mandatory=$true)]
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

    if ([string]::IsNullOrWhiteSpace($IPAddress) -and [string]::IsNullOrWhiteSpace($Hostname) -and $Port -le 0) {
        return "bindings.[protocol='$($Protocol)']"
    }

    $str = [string]::Empty

    switch ($Protocol.ToLowerInvariant()) {
        'net.tcp' {
            $str = "$($Port):$($Hostname)"
        }

        { @('net.msmq', 'net.pipe', 'msmq.formatname') -icontains $_ } {
            $str = "$($Hostname)"
        }

        default {
            $str = "$($IPAddress):$($Port):$($Hostname)"
        }
    }

    return "bindings.[protocol='$($Protocol)',bindingInformation='$($str)']"
}

function Wait-IISMBackgroundTask
{
    param (
        [Parameter(Mandatory=$true)]
        [scriptblock]
        $ScriptBlock
    )

    foreach ($i in (0..10)) {
        $result = (. $ScriptBlock)
        if ($result) {
            return
        }

        Start-Sleep -Milliseconds 500
    }

    throw 'Object not created in time'
}

function Add-IISMSlash
{
    param (
        [Parameter()]
        [string]
        $Value,

        [switch]
        $CheckNonEmpty,

        [switch]
        $Append
    )

    if ($CheckNonEmpty -and [string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    if ($Append) {
        if (!$Value.EndsWith('/')) {
            $Value = "$($Value)/"
        }
    }
    else {
        if (!$Value.StartsWith('/')) {
            $Value = "/$($Value)"
        }
    }

    return $Value
}