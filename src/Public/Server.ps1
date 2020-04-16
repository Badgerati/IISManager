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

    # build the command
    $auth = "[name='$($Name)']"

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:system.ftpServer/providerDefinitions /-`"$($auth)`"" -NoParse | Out-Null
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

    # build the command
    $_args = "/-`"siteDefaults.ftpServer.security.authentication.customAuthentication.providers.[name='$($ProviderName)']`""

    # run the command
    Invoke-IISMAppCommand -Arguments "set config /section:sites $($_args)" -NoParse | Out-Null
}