function Get-IISMDirectories
{
    param (
        [Parameter()]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName,

        [Parameter()]
        [Alias('p')]
        [string]
        $PhysicalPath
    )

    $AppName = Add-IISMSlash -Value $AppName
    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append

    # get either one dir, or all dirs
    if (![string]::IsNullOrWhiteSpace($SiteName)) {
        $result = Invoke-IISMAppCommand -Arguments "list vdir '$($Name)'" -NoError
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list vdirs' -NoError
    }

    # just return if there are no results
    if ($null -eq $result) {
        return $null
    }

    $dirs = ConvertTo-IISMDirectoryObject -Directories $result.VDIR

    # if we have a physical path, filter dirs
    if (![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        $dirs = @($dirs | Where-Object { $_.PhysicalPath -ieq $PhysicalPath })
    }

    return $dirs
}

function Test-IISMDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/'
    )

    $AppName = Add-IISMSlash -Value $AppName
    return ($null -ne (Get-IISMDirectories -SiteName $SiteName -AppName $AppName))
}

function Remove-IISMDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/'
    )

    $AppName = Add-IISMSlash -Value $AppName
    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append

    if (Test-IISMDirectory -SiteName $SiteName -AppName $Name) {
        Invoke-IISMAppCommand -Arguments "delete vdir '$($Name)'" -NoParse | Out-Null
    }

    return (Get-IISMDirectories)
}

function New-IISMDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/',

        [Parameter(Mandatory=$true)]
        [Alias('p')]
        [string]
        $PhysicalPath,

        [switch]
        $CreatePath
    )

    $AppName = Add-IISMSlash -Value $AppName
    $FullAppName = "$($SiteName)$($AppName)"
    $DirName = Add-IISMSlash -Value $FullAppName -Append

    # error if directory already exists
    if (Test-IISMDirectory -SiteName $SiteName -AppName $AppName) {
        throw "Directory '$($DirName)' already exists in IIS"
    }

    # error if the app doesn't exist
    if (!(Test-IISMApp -SiteName $SiteName -Name $AppName)) {
        throw "Application '$($FullAppName)' does not exist in IIS"
    }

    # if create flag passed, make the path
    if ($CreatePath -and !(Test-Path $PhysicalPath)) {
        New-Item -Path $PhysicalPath -ItemType Directory -Force | Out-Null
    }

    # create the directory
    $_args = "/app.name:'$($FullAppName)' /physicalPath:'$($PhysicalPath)'"
    Invoke-IISMAppCommand -Arguments "add vdir $($_args)" -NoParse | Out-Null
    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMDirectory -SiteName $SiteName -AppName $AppName }

    # return the directory
    return (Get-IISMDirectories -SiteName $SiteName -AppName $AppName)

}

function Update-IISMDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/',

        [Parameter()]
        [Alias('p')]
        [string]
        $PhysicalPath
    )

    $AppName = Add-IISMSlash -Value $AppName
    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # update the physical path
    if (![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        Invoke-IISMAppCommand -Arguments "set vdir '$($Name)' /physicalPath:'$($PhysicalPath)'" -NoParse | Out-Null
    }

    # return the directory
    return (Get-IISMDirectories -SiteName $SiteName -AppName $AppName)
}

function Update-IISMDirectoryPhysicalPaths
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $From,

        [Parameter(Mandatory=$true)]
        [string]
        $To
    )

    # get all directories with the From path
    $dirs = Get-IISMDirectories -PhysicalPath $From

    # update each dir
    $dirs | ForEach-Object {
        $_atoms = @($_.Name -split '/')
        if ($_atoms.Length -eq 1) {
            $siteName = $_atoms[0]
            $appName = '/'
        }
        else {
            $siteName = $_atoms[0]
            $appName = ($_atoms[1..($_atoms.Length - 1)] -join '/')
        }

        Update-IISMDirectory -SiteName $siteName -AppName $appName -PhysicalPath $To | Out-Null
    }

    # return the directories
    return (Get-IISMDirectories -PhysicalPath $To)
}

function Mount-IISMDirectoryShare
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $Permission = 'Everyone,FULL'
    )

    $AppName = Add-IISMSlash -Value $AppName

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $SiteName)) {
        throw "Website '$($SiteName)' does not exist in IIS"
    }

    # error if the app doesn't exist
    if (!(Test-IISMApp -SiteName $SiteName -Name $AppName)) {
        throw "Application '$($SiteName)$($AppName)' does not exist in IIS"
    }

    # get the physical path for the site/app
    $path = Get-IISMSitePhysicalPath -Name $SiteName -AppName $AppName

    # error if the path doesn't exist
    if ([string]::IsNullOrWhiteSpace($path) -or !(Test-Path $path)) {
        throw "The path for sharing does not exist: $($path)"
    }

    # make the share name
    $ShareName = ("$($SiteName)$($AppName)".Trim('\/') -replace '[\\/]', '.')

    # if the share exists, remove it
    Remove-IISMDirectoryShare -SiteName $SiteName -AppName $AppName

    # create the share
    Invoke-IISMNetCommand -Arguments "share $($ShareName)=$($path) /grant:`"$($Permission)`"" | Out-Null

    # return the share details
    return (Get-IISMDirectoryShare -SiteName $SiteName -AppName $AppName)
}

function Remove-IISMDirectoryShare
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/'
    )

    # make the share name
    $AppName = Add-IISMSlash -Value $AppName
    $ShareName = ("$($SiteName)$($AppName)".Trim('\/') -replace '[\\/]', '.')

    # if the share exists, remove it
    if (Test-IISMDirectoryShare -SiteName $SiteName -AppName $AppName) {
        Invoke-IISMNetCommand -Arguments "share $($ShareName) /delete /y" | Out-Null
    }
}

function Test-IISMDirectoryShare
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/'
    )

    return ($null -ne (Get-IISMDirectoryShare -SiteName $SiteName -AppName $AppName))
}

function Get-IISMDirectoryShare
{
    param (
        [Parameter(Mandatory=$true)]
        [Alias('sn')]
        [string]
        $SiteName,

        [Parameter()]
        [Alias('an')]
        [string]
        $AppName = '/'
    )

    # make the share name
    $AppName = Add-IISMSlash -Value $AppName
    $ShareName = ("$($SiteName)$($AppName)".Trim('\/') -replace '[\\/]', '.')

    # check if the share exists
    $share = (Invoke-IISMNetCommand -Arguments "share $($ShareName)" -NoError)
    if (($LASTEXITCODE -ne 0) -or ($share -ilike '*does not exist*')) {
        return $null
    }

    # if it exists, parse the data
    $obj = New-Object -TypeName psobject
    $culture = (Get-Culture).TextInfo

    @($share -imatch '\s{2,}') | ForEach-Object {
        $atoms = $_ -split '\s{2,}'
        $name = ($culture.ToTitleCase($atoms[0]) -ireplace '\s+', '')
        $obj | Add-Member -MemberType NoteProperty -Name $name -Value $atoms[1]
    }

    return $obj
}