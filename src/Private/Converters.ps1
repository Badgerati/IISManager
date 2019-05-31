function ConvertTo-IISMSiteObject
{
    param (
        [Parameter()]
        $Sites,

        [Parameter()]
        $Apps
    )

    $mapped = @()

    foreach ($site in $Sites) {
        $_apps = @()
        $Apps | Where-Object { $_.SiteName -ieq $site.'SITE.NAME' } | ForEach-Object {
            $_apps += $_
        }

        $_bindings = @($site.site.bindings.binding | ForEach-Object {
            Get-IISMSiteBindingInformation -Binding $_
        })

        $obj = (New-Object -TypeName psobject |
            Add-Member -MemberType NoteProperty -Name ID -Value $site.'SITE.ID' -PassThru |
            Add-Member -MemberType NoteProperty -Name Name -Value $site.'SITE.NAME' -PassThru |
            Add-Member -MemberType NoteProperty -Name Bindings -Value @($_bindings) -PassThru |
            Add-Member -MemberType NoteProperty -Name State -Value $site.state -PassThru |
            Add-Member -MemberType NoteProperty -Name Apps -Value $_apps -PassThru |
            Add-Member -MemberType NoteProperty -Name Limits -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name LogFile -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name TraceFailedRequestsLogging -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name Hsts -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name ApplicationDefaults -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name FTPServer -Value $null -PassThru)

        $mapped +=  $obj
    }

    return $mapped
}

function ConvertTo-IISMAppPoolObject
{
    param (
        [Parameter()]
        $AppPools
    )

    $mapped = @()

    foreach ($pool in $AppPools) {
        $obj = (New-Object -TypeName psobject |
            Add-Member -MemberType NoteProperty -Name Name -Value $pool.'APPPOOL.NAME' -PassThru |
            Add-Member -MemberType NoteProperty -Name PipelineMode -Value $pool.PipelineMode -PassThru |
            Add-Member -MemberType NoteProperty -Name RuntimeVersion -Value $pool.RuntimeVersion -PassThru |
            Add-Member -MemberType NoteProperty -Name State -Value $pool.state -PassThru |
            Add-Member -MemberType NoteProperty -Name ProcessModel -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name Recycling -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name Failure -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name CPU -Value $null -PassThru |
            Add-Member -MemberType NoteProperty -Name EnvironmentVariables -Value $null -PassThru)

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMAppObject
{
    param (
        [Parameter()]
        $Apps,

        [Parameter()]
        $AppPools,

        [Parameter()]
        $Directories
    )

    $mapped = @()

    foreach ($app in $Apps) {
        $_pool = ($AppPools | Where-Object { $_.Name -ieq $app.'APPPOOL.NAME' } | Select-Object -First 1)
        $_dir = ($Directories | Where-Object { $_.AppName -ieq $app.'APP.NAME' } | Select-Object -First 1)

        $obj = (New-Object -TypeName psobject |
            Add-Member -MemberType NoteProperty -Name Name -Value $app.'APP.NAME' -PassThru |
            Add-Member -MemberType NoteProperty -Name Path -Value $app.path -PassThru |
            Add-Member -MemberType NoteProperty -Name AppPool -Value $_pool -PassThru |
            Add-Member -MemberType NoteProperty -Name SiteName -Value $app.'SITE.NAME' -PassThru |
            Add-Member -MemberType NoteProperty -Name Directory -Value $_dir -PassThru)

        $mapped += $obj
    }

    return $mapped
}

function ConvertTo-IISMDirectoryObject
{
    param (
        [Parameter()]
        $Directories
    )

    $mapped = @()

    foreach ($dir in $Directories) {
        $obj = (New-Object -TypeName psobject |
            Add-Member -MemberType NoteProperty -Name Name -Value $dir.'VDIR.NAME' -PassThru |
            Add-Member -MemberType NoteProperty -Name PhysicalPath -Value $dir.physicalPath -PassThru |
            Add-Member -MemberType NoteProperty -Name Path -Value $dir.path -PassThru |
            Add-Member -MemberType NoteProperty -Name AppName -Value $dir.'APP.NAME' -PassThru)

        $mapped += $obj
    }

    return $mapped
}
