function Reset-IISMServer
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName
    )

    Invoke-IISMResetCommand -Arguments "$($ComputerName)" | Out-Null
}

function Get-IISMCertificateThumbprint
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $CertificateName
    )

    # if linux, fail
    if (Test-IsUnix) {
        throw 'This function cannot be used on *nix environments'
    }

    # add wildcards
    if (!$CertificateName.StartsWith('*')) {
        $CertificateName = "*$($CertificateName)"
    }

    if (!$CertificateName.EndsWith('*')) {
        $CertificateName = "$($CertificateName)*"
    }

    # get the cert from the store
    $cert = (Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object {
        $_.Subject -ilike $CertificateName
    } | Select-Object -First 1)

    if ([string]::IsNullOrWhiteSpace($cert)) {
        return $null
    }

    return $cert.Thumbprint.ToString()
}

function New-IISMCredentials
{
    [CmdletBinding()]
    [OutputType([pscredential])]
    param(
        [Parameter()]
        [string]
        $Username,

        [Parameter()]
        [string]
        $Password
    )

    if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
        return $null
    }

    return (New-Object System.Management.Automation.PSCredential -ArgumentList $Username, (ConvertTo-SecureString -AsPlainText $Password -Force))
}

function Invoke-IISMAppCommand
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Arguments,

        [switch]
        $NoParse,

        [switch]
        $NoError
    )
    
    Write-Verbose $Arguments

    # run the command
    if ($NoParse) {
        $result = (Invoke-Expression -Command "$(Get-IISMAppCmdPath) $Arguments")
    }
    else {
        $result = (Invoke-Expression -Command "$(Get-IISMAppCmdPath) $Arguments /xml /config")
    }

    # check for errors
    if (($LASTEXITCODE -ne 0) -and !$NoError) {
        throw "Failed to run appcmd: $($result)"
    }

    # parse, if needed
    if (!$NoParse) {
        $result = ([xml]$result).appcmd
    }
    return $result
}