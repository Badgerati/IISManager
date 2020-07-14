function Get-IISMServerFtpCustomAuthenticationProvider
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Name
    )

    $result = Invoke-IISMAppCommand -Arguments 'list config /section:system.ftpServer/providerDefinitions' -NoError

    $providers = @(foreach ($provider in $result.CONFIG.'system.ftpServer-providerDefinitions'.add) {
        if (![string]::IsNullOrWhiteSpace($Name) -and ($provider.name -ine $Name)) {
            continue
        }

        @{
            Name = $provider.name
            Type = $provider.type
            ClassId = $provider.clsid
        }
    })

    return $providers
}

function Register-IISMServerFtpCustomAuthenticationProvider
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true, ParameterSetName='ClassId')]
        [string]
        $ClassId,

        [Parameter(Mandatory=$true, ParameterSetName='Type')]
        [string]
        $Type
    )

    # first, remove it, in case the details are different
    Unregister-IISMServerFtpCustomAuthenticationProvider -Name $Name

    # build the command for the auth type
    switch ($PSCmdlet.ParameterSetName) {
        'ClassId' {
            $auth = "[name='$($Name)',clsid='$($ClassId)']"
        }

        'Type' {
            $auth = "[name='$($Name)',type='$($Type)']"
        }
    }

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:system.ftpServer/providerDefinitions /+`"$($auth)`"" -NoParse | Out-Null
}

function Unregister-IISMServerFtpCustomAuthenticationProvider
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    # do nothing if it doesn't exist
    $auth = Get-IISMServerFtpCustomAuthenticationProvider -Name $Name
    if (($null -eq $auth) -or ($auth.Length -eq 0)) {
        return
    }

    # build the command
    $auth = "[name='$($Name)']"

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:system.ftpServer/providerDefinitions /-`"$($auth)`"" -NoParse | Out-Null
}

function Get-IISMServerFtpCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $ProviderName
    )

    $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
    $providers = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.ftpServer.security.authentication.customAuthentication.providers.add

    if (($null -eq $providers) -or ($providers.Length -eq 0)) {
        return $null
    }

    $_providers = @(foreach ($provider in $providers) {
        @{
            Name = $provider.name
            Enabled = ($provider.enabled -ieq 'true')
        }
    })

    if ([string]::IsNullOrWhiteSpace($ProviderName)) {
        return $_providers
    }

    return ($_providers | Where-Object { $_.Name -ieq $ProviderName })
}

function Add-IISMServerFtpCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $ProviderName,

        [switch]
        $Enable
    )

    # remove it first
    Remove-IISMServerFtpCustomAuthentication -ProviderName $ProviderName

    # build the command
    $_args = "/+`"siteDefaults.ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)',enabled='$($Enable.IsPresent)']`""

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:sites $($_args)" -NoParse | Out-Null
}

function Remove-IISMServerFtpCustomAuthentication
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $ProviderName
    )

    # do nothing if it doesn't exist
    $prov = Get-IISMServerFtpCustomAuthentication -ProviderName $ProviderName
    if (($null -eq $prov) -or ($prov.Length -eq 0)) {
        return
    }

    # build the command
    $_args = "/-`"siteDefaults.ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)']`""

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:sites $($_args)" -NoParse | Out-Null
}