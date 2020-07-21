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
            $logPeriod = Get-IISMSiteLogPeriod -Name $Name
        }

        default {
            $logFields = Get-IISMSiteLogFields -Default
            $logCustomFields = Get-IISMSiteCustomLogFields -Default
            $logFormat = Get-IISMSiteLogFormat -Default
            $logPath = Get-IISMSiteLogPath -Default
            $logPeriod = Get-IISMSiteLogPeriod -Default
        }
    }

    return (ConvertTo-IISMSiteLoggingObject `
        -Fields $logFields `
        -CustomFields $logCustomFields `
        -Format $logFormat `
        -Path $logPath `
        -Period $logPeriod)
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

function Get-IISMSiteLogPeriod
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

            $period = $result.SITE.site.logFile.period
            if ([string]::IsNullOrWhiteSpace($period)) {
                $period = Get-IISMSiteLogPeriod -Default
            }
        }

        default {
            $result = Invoke-IISMAppCommand -Arguments "list config /section:sites" -NoError
            $period = $result.CONFIG.'system.applicationHost-sites'.siteDefaults.logFile.period
            $period = (Protect-IISMValue $period 'Daily')
        }
    }

    return $period
}

function Set-IISMSiteLogPeriod
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Hourly', 'Daily', 'Weekly', 'Monthly')]
        [string]
        $Period,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].logFile.period:$($Period)`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"siteDefaults.logFile.period:$($Period)`"" -NoParse | Out-Null
        }
    }
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

function Set-IISMSiteLogPath
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='Site')]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter(ParameterSetName='Default')]
        [switch]
        $Default
    )

    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].logFile.directory:$($Path)`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"siteDefaults.logFile.directory:$($Path)`"" -NoParse | Out-Null
        }
    }
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

    return ($fields -split ',').Trim()
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

            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"[name='$($Name)'].logFile.logExtFileFlags:$($Fields -join ',')`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /`"siteDefaults.logFile.logExtFileFlags:$($Fields -join ',')`"" -NoParse | Out-Null
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

function Clear-IISMSiteLogFields
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
            Set-IISMSiteLogFields -Name $Name -Fields @()
        }

        default {
            Set-IISMSiteLogFields -Default -Fields @()
        }
    }
}

function Test-IISMSiteLogField
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

    # get current fields
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = Get-IISMSiteLogFields -Name $Name
        }

        default {
            $fields = Get-IISMSiteLogFields -Default
        }
    }

    return ($fields -icontains $Field)
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

    # skip if it already exists
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $exists = (Test-IISMSiteCustomLogField -Name $Name -Field $Field)
        }

        default {
            $exists = (Test-IISMSiteCustomLogField -Default -Field $Field)
        }
    }

    if ($exists) {
        return
    }

    # set source as field
    if ([string]::IsNullOrWhiteSpace($Source)) {
        $Source = $Field
    }

    # add the custom field
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            if (!(Test-IISMSite -Name $Name)) {
                throw "Website '$($Name)' does not exist in IIS"
            }

            Invoke-IISMAppCommand -Arguments "set config /section:sites /+`"[name='$($Name)'].logFile.customFields.[logFieldName='$($Field)',sourceName='$($Source)',sourceType='$($Type)']`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /+`"siteDefaults.logFile.customFields.[logFieldName='$($Field)',sourceName='$($Source)',sourceType='$($Type)']`"" -NoParse | Out-Null
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

            Invoke-IISMAppCommand -Arguments "set config /section:sites /-`"[name='$($Name)'].logFile.customFields.[logFieldName='$($Field)']`"" -NoParse | Out-Null
        }

        default {
            Invoke-IISMAppCommand -Arguments "set config /section:sites /-`"siteDefaults.logFile.customFields.[logFieldName='$($Field)']`"" -NoParse | Out-Null
        }
    }
}

function Clear-IISMSiteCustomLogFields
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

    # get current fields
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = Get-IISMSiteCustomLogFields -Name $Name
        }

        default {
            $fields = Get-IISMSiteCustomLogFields -Default
        }
    }

    # go through each one and remove them
    foreach ($field in $fields) {
        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'site' {
                Remove-IISMSiteCustomLogField -Name $Name -Field $field.Name
            }

            default {
                Remove-IISMSiteCustomLogField -Default -Field $field.Name
            }
        }
    }
}

function Test-IISMSiteCustomLogField
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

    # get current fields
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'site' {
            $fields = Get-IISMSiteCustomLogFields -Name $Name
        }

        default {
            $fields = Get-IISMSiteCustomLogFields -Default
        }
    }

    return (@($fields | Where-Object { $_.Name -ieq $Field }).Length -eq 1)
}