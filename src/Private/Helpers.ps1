function Write-IISWarning
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

function Invoke-IISAppCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments,

        [switch]
        $NoParse
    )

    if ($NoParse) {
        return (Invoke-Expression -Command "$(Get-IISAppCmdPath) $Arguments")
    }
    else {
        return ([xml](Invoke-Expression -Command "$(Get-IISAppCmdPath) $Arguments /xml")).appcmd
    }
}

function Invoke-IISNetshCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments
    )

    return (Invoke-Expression -Command "$(Get-IISNetshPath) $Arguments")
}

function Get-IISSiteBindingInformation
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Binding
    )

    # get the protocol
    $split = ($Binding -split '/')
    $protocol = $split[0]

    # reset binding
    $Binding = ($split[1] -join '')

    # get ip, port, hostname
    $split = ($Binding -split ':')
    $ip = $split[0]
    $port = $split[1]
    $hostname = $split[2]

    # get cert info for https
    $cert = $null
    if ($protocol -ieq 'https') {
        #/mnt/c/Windows/System32/netsh.exe http show sslcert

        # get netsh details
        $details = (Invoke-IISNetshCommand -Arguments "http show sslcert ipport=$($ip):$($port)")
        if ($LASTEXITCODE -ne 0 -and ![string]::IsNullOrWhiteSpace($hostname)) {
            $details = (Invoke-IISNetshCommand -Arguments "http show sslcert hostnameport=$($hostname):$($port)")
        }

        # get thumbprint
        $thumbprint = (($details -imatch 'Certificate Hash\s+:\s+([a-z0-9]+)') -split ':')[1].Trim()

        # get cert subject
        if (!(Test-IsUnix)) {
            $subject = (Get-ChildItem "Cert:/LocalMachine/My/$($t)").Subject
        }

        # set the cert
        $cert = (New-Object -TypeName psobject |
            Add-Member -MemberType NoteProperty -Name Thumbprint -Value $thumbprint -PassThru |
            Add-Member -MemberType NoteProperty -Name Subject -Value $subject -PassThru)
    }

    # set the binding info and return
    $info = (New-Object -TypeName psobject |
        Add-Member -MemberType NoteProperty -Name Protocol -Value $protocol -PassThru |
        Add-Member -MemberType NoteProperty -Name IPAddress -Value $ip -PassThru |
        Add-Member -MemberType NoteProperty -Name Port -Value $port -PassThru |
        Add-Member -MemberType NoteProperty -Name Hostname -Value $hostname -PassThru |
        Add-Member -MemberType NoteProperty -Name Certificate -Value $cert -PassThru)

    return $info
}

function Wait-IISBackgroundTask
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