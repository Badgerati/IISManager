function Get-IISMSiteLogging
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $logFields = Get-IISMSiteLogFields -Name $Name
            $logCustomFields = Get-IISMSiteCustomLogFields -Name $Name
            $logFormat = Get-IISMSiteLogFormat -Name $Name
            $logPath = Get-IISMSiteLogPath -Name $Name
        }

        default {
            $logFields = Get-IISMSiteLogFields -Default
            $logCustomFields = Get-IISMSiteCustomLogFields -Default
            $logFormat = Get-IISMSiteLogFormat -Default
            $logPath = Get-IISMSiteLogPath -Default
        }
    }

    return (ConvertTo-IISMSiteLoggingObject -Fields $logFields -CustomFields $logCustomFields -Format $logFormat -PAth $logPath)
}

function Get-IISMSiteLogFormat
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $format = $result.SITE.site.logFile.logFormat
            if ([string]::IsNullOrWhiteSpace($format)) {
                $format = Get-IISMSiteLogFormat -Default
            }
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $format = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.logFile.logFormat
            $format = (Protect-IISMValue $format 'W3C')
        }
    }

    return $format
}

function Get-IISMSiteLogPath
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $logpath = $result.SITE.site.logFile.directory
            if ([string]::IsNullOrWhiteSpace($logpath)) {
                $logpath = Get-IISMSiteLogPath -Default
            }

            $logpath = (Join-Path $logpath "W3SVC$($result.SITE.site.id)")
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $logpath = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.logFile.directory
            $logpath = (Protect-IISMValue $logpath (Get-IISMSiteDefaultLogPath))
        }
    }

    return [System.Environment]::ExpandEnvironmentVariables($logpath)
}

function Get-IISMSiteLogFields
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $fields = $result.SITE.site.logFile.logExtFileFlags
            if ([string]::IsNullOrWhiteSpace($fields)) {
                $fields = Get-IISMSiteLogFields -Default
            }
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $fields = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.logFile.logExtFileFlags
            $fields = (Protect-IISMValue $fields (Get-IISMSiteDefaultLogFields))
        }
    }

    return ($fields -split ',')
}

function Set-IISMSiteLogFields
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string[]]
        $Fields,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].logfile.logExtFileFlags:$($Fields -join ',')`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /siteDefaults.logfile.logExtFileFlags:$($Fields -join ',')" -NoParse | Out-Null
        }
    }
}

function Add-IISMSiteLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = Get-IISMSiteLogFields -Name $Name
            if ($fields -inotcontains $Field) {
                $fields += $Field
            }

            Set-IISMSiteLogFields -Name $Name -Fields $fields
        }

        default {
            $fields = Get-IISMSiteLogFields -Default
            if ($fields -inotcontains $Field) {
                $fields += $Field
            }

            Set-IISMSiteLogFields -Default -Fields $fields
        }
    }
}

function Remove-IISMSiteLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = (Get-IISMSiteLogFields -Name $Name | Where-Object { $_ -ine $Field })
            Set-IISMSiteLogFields -Name $Name -Fields $fields
        }

        default {
            $fields = (Get-IISMSiteLogFields -Default | Where-Object { $_ -ine $Field })
            Set-IISMSiteLogFields -Default -Fields $fields
        }
    }
}

function Get-IISMSiteCustomLogFields
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            $result = Invoke-IISMAppCommand -Arguments "list site '$Name'" -NoError

            $fields = $result.SITE.site.logFile.customFields.add
            if ([string]::IsNullOrWhiteSpace($fields)) {
                $fields = Get-IISMSiteCustomLogFields -Default
            }
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $fields = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.logFile.customFields.add
        }
    }

    return (ConvertTo-IISMSiteCustomLogFieldObject -Fields $fields)
}

function Add-IISMSiteCustomLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(Mandatory=$true)]
        [ValidateSet('RequestHeader', 'ResponseHeader', 'ServerVariable')]
        [string]
        $Type,

        [Parameter()]
        [string]
        $Source,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        $Source = $Field
    }

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /+`"[name='$($Name)'].logfile.customFields.[logFieldName='$($Field)',sourceName='$($Source)',sourceType='$($Type)']`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /+`"siteDefaults.logfile.customFields.[logFieldName='$($Field)',sourceName='$($Source)',sourceType='$($Type)']`"" -NoParse | Out-Null
        }
    }
}

function Remove-IISMSiteCustomLogField
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Field,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /-`"[name='$($Name)'].logfile.customFields.[logFieldName='$($Field)']`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /-`"siteDefaults.logfile.customFields.[logFieldName='$($Field)']`"" -NoParse | Out-Null
        }
    }
}