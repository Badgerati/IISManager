function Get-IISMDirectories
{
    param (
        [Parameter()]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName,

        [Parameter()]
        [string]
        $PhysicalPath
    )

    $AppName = Add-IISMSlash -Value $AppName
    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append

    # get either one dir, or all dirs
    if (![string]::IsNullOrWhiteSpace($SiteName)) {
        $result = Invoke-IISMAppCommand -Arguments "list vdir '$($Name)'"
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list vdirs'
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
        [string]
        $SiteName,

        [Parameter()]
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
        [string]
        $SiteName,

        [Parameter()]
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
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $PhysicalPath
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
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
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

function Set-IISMDirectoryShare
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Permission = 'Everyone,FULL'
    )

    # error if the path doesn't exist
    if (!(Test-Path $Path)) {
        throw "The path for sharing does not exist: $($Path)"
    }

    # make the share name
    $AppName = Add-IISMSlash -Value $AppName
    $ShareName = ("$($SiteName)$($AppName)".Trim('\/') -replace '[\\/]', '.')

    # if the share exists, remove it
    $shares = (Invoke-IISMNetCommand -Arguments "share")
    if (($shares | Where-Object { $_ -ilike "$($ShareName)*" } | Measure-Object).Count -gt 0) {
        Invoke-IISMNetCommand -Arguments "share $($ShareName) /delete /y 2>&1>null" | Out-Null
    }

    # create the share
    Invoke-IISMNetCommand -Arguments "share $($ShareName)=$($Path) /grant:`"$($Permission)`" 2>&1>null" | Out-Null
}