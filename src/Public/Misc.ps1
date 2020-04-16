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
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $CertificateName
    )

    # if linux, fail
    if (Test-IsUnix) {
        throw 'This function cannot be used on *nix environments'
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