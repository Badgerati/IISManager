function Get-IISMDirectory
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter()]
        [string]
        $PhysicalPath,

        [switch]
        $Quick
    )

    $AppName = Add-IISMSlash -Value $AppName
    $Name = "$($SiteName)$($AppName)"

    # get the directories
    $result = (Invoke-IISMAppCommand -Arguments 'list vdirs' -NoError)

    # just return if there are no results
    if ($null -eq $result.VDIR) {
        return $null
    }

    $dirs = ConvertTo-IISMDirectoryObject -Directories $result.VDIR -Quick:$Quick

    # filter by site/app
    if (![string]::IsNullOrWhiteSpace($SiteName)) {
        $dirs = @($dirs | Where-Object { $_.AppName -ieq $Name })
    }

    # then filter by dir
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $DirName = Add-IISMSlash -Value $DirName
        $dirs = @($dirs | Where-Object { $_.Path -ieq $DirName })
    }

    # if we have a physical path, filter dirs
    if (![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        $dirs = @($dirs | Where-Object { $_.PhysicalPath -ieq $PhysicalPath })
    }

    return $dirs
}

function Test-IISMDirectory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    return ($null -ne (Get-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName -Quick))
}

function Remove-IISMDirectory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [switch]
        $NoOutput
    )

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    if (Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName) {
        Invoke-IISMAppCommand -Arguments "delete vdir '$($Name)'" -NoParse | Out-Null
    }

    if (!$NoOutput) {
        return (Get-IISMDirectory)
    }
}

function New-IISMDirectory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter(Mandatory=$true)]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [string]
        $PhysicalPath,

        [Parameter()]
        [pscredential]
        $Credentials,

        [switch]
        $CreatePath,

        [switch]
        $NoOutput
    )

    $AppName = Add-IISMSlash -Value $AppName
    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    $FullDirName = "$($Name)$($DirName)"

    # error if directory already exists
    if (Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName) {
        throw "Directory '$($FullDirName)' already exists in IIS"
    }

    # error if the app doesn't exist
    if (!(Test-IISMApp -SiteName $SiteName -Name $AppName)) {
        throw "Application '$($Name)' does not exist in IIS"
    }

    # if create flag passed, make the path
    if ($CreatePath -and !(Test-Path $PhysicalPath)) {
        New-Item -Path $PhysicalPath -ItemType Directory -Force | Out-Null
    }

    # create the directory
    $_dirName = Add-IISMSlash -Value $DirName
    $_args = "/app.name:'$($Name)' /path:'$($_dirName)' /physicalPath:'$($PhysicalPath)'"

    Invoke-IISMAppCommand -Arguments "add vdir $($_args)" -NoParse | Out-Null
    Wait-IISMBackgroundTask -ScriptBlock { Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName }

    # set the creds
    if ($null -ne $Credentials) {
        Set-IISMDirectoryCredentials -SiteName $SiteName -AppName $AppName -DirName $DirName -Credentials $Credentials
    }

    # return the directory
    if (!$NoOutput) {
        return (Get-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Update-IISMDirectory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter()]
        [string]
        $PhysicalPath,

        [Parameter()]
        [pscredential]
        $Credentials,

        [switch]
        $NoOutput
    )

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # update the physical path
    if (![string]::IsNullOrWhiteSpace($PhysicalPath)) {
        Invoke-IISMAppCommand -Arguments "set vdir '$($Name)' /physicalPath:'$($PhysicalPath)'" -NoParse | Out-Null
    }

    # update the credentials
    if ($null -ne $Credentials) {
        Set-IISMDirectoryCredentials -SiteName $SiteName -AppName $AppName -DirName $DirName -Credentials $Credentials
    }

    # return the directory
    if (!$NoOutput) {
        return (Get-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Update-IISMDirectoryPhysicalPaths
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $From,

        [Parameter(Mandatory=$true)]
        [string]
        $To,

        [switch]
        $NoOutput
    )

    # get all directories with the From path
    $dirs = Get-IISMDirectory -PhysicalPath $From

    # update each dir
    foreach ($dir in $dirs) {
        $info = Split-IISMDirectoryName -DirName $dir.Name
        Update-IISMDirectory -SiteName $info.SiteName -AppName $info.AppName -DirName $info.DirName -PhysicalPath $To | Out-Null
    }

    # return the directories
    if (!$NoOutput) {
        return (Get-IISMDirectory -PhysicalPath $To)
    }
}

function Mount-IISMDirectoryShare
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter()]
        [string]
        $Permission = 'Everyone,FULL',

        [switch]
        $NoOutput
    )

    $AppName = Add-IISMSlash -Value $AppName
    $DirName = Add-IISMSlash -Value $DirName

    # error if the site doesn't exist
    if (!(Test-IISMSite -Name $SiteName)) {
        throw "Website '$($SiteName)' does not exist in IIS"
    }

    # error if the app doesn't exist
    if (!(Test-IISMApp -SiteName $SiteName -Name $AppName)) {
        throw "Application '$($SiteName)$($AppName)' does not exist in IIS"
    }

    # get the physical path for the site/app
    $path = Get-IISMSitePhysicalPath -Name $SiteName -AppName $AppName -DirName $DirName

    # error if the path doesn't exist
    if ([string]::IsNullOrWhiteSpace($path) -or !(Test-Path $path)) {
        throw "The path for sharing does not exist: $($path)"
    }

    # make the share name
    $ShareName = ("$($SiteName)$($AppName)$($DirName)".Trim('\/') -replace '[\\/]', '.')

    # if the share exists, remove it
    Remove-IISMDirectoryShare -SiteName $SiteName -AppName $AppName -DirName $DirName

    # create the share
    Invoke-IISMNetCommand -Arguments "share $($ShareName)=$($path) /grant:`"$($Permission)`"" | Out-Null

    # return the share details
    if (!$NoOutput) {
        return (Get-IISMDirectoryShare -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Remove-IISMDirectoryShare
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    # make the share name
    $AppName = Add-IISMSlash -Value $AppName
    $DirName = Add-IISMSlash -Value $DirName
    $ShareName = ("$($SiteName)$($AppName)$($DirName)".Trim('\/') -replace '[\\/]', '.')

    # if the share exists, remove it
    if (Test-IISMDirectoryShare -SiteName $SiteName -AppName $AppName -DirName $DirName) {
        Invoke-IISMNetCommand -Arguments "share $($ShareName) /delete /y" | Out-Null
    }
}

function Test-IISMDirectoryShare
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    return ($null -ne (Get-IISMDirectoryShare -SiteName $SiteName -AppName $AppName -DirName $DirName))
}

function Get-IISMDirectoryShare
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    # make the share name
    $AppName = Add-IISMSlash -Value $AppName
    $DirName = Add-IISMSlash -Value $DirName
    $ShareName = ("$($SiteName)$($AppName)$($DirName)".Trim('\/') -replace '[\\/]', '.')

    # check if the share exists
    $share = (Invoke-IISMNetCommand -Arguments "share $($ShareName)" -NoError)
    if (($LASTEXITCODE -ne 0) -or ($share -ilike '*does not exist*')) {
        return $null
    }

    # if it exists, parse the data
    $obj = @{}
    $culture = (Get-Culture).TextInfo

    foreach ($shr in @($share -imatch '\s{2,}')) {
        $atoms = ($shr -split '\s{2,}')
        $name = ($culture.ToTitleCase($atoms[0]) -ireplace '\s+', '')
        $obj[$name] = $atoms[1]
    }

    return $obj
}

function Set-IISMDirectoryCredentials
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credentials
    )

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # update the credentials
    if ($null -ne $Credentials) {
        $creds = Get-IISMCredentialDetails -Credentials $Credentials
        Invoke-IISMAppCommand -Arguments "set vdir '$($Name)' /userName:$($creds.username) /password:$($creds.password)" -NoParse | Out-Null
    }
}

function Get-IISMDirectoryFtpAuthorization
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    return (Get-IISMDirectoryFtpAuthorizationInternal -Name $Name)
}

function Add-IISMDirectoryFtpAuthorization
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Read', 'Write')]
        [string[]]
        $Permission,

        [Parameter()]
        [string[]]
        $User,

        [Parameter()]
        [string[]]
        $Role,

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it already has the auth
    $current = (Get-IISMDirectoryFtpAuthorizationInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.Users -join ',') -ieq ($User -join ',') -and
        ($_.Roles -join ',') -ieq ($Role -join ',') -and
        ($_.Permissions -join ',') -ieq ($Permission -join ',')
    })

    if ($null -ne $check) {
        return
    }

    # add the auth
    $auth = Get-IISMFtpAuthorizationCommandString -AccessType $AccessType -Permission $Permission -User $User -Role $Role
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/authorization /+`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMDirectoryFtpAuthorization -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Remove-IISMDirectoryFtpAuthorization
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Read', 'Write')]
        [string[]]
        $Permission,

        [Parameter()]
        [string[]]
        $User,

        [Parameter()]
        [string[]]
        $Role,

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it doesnt have the auth
    $current = (Get-IISMDirectoryFtpAuthorizationInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.Users -join ',') -ieq ($User -join ',') -and
        ($_.Roles -join ',') -ieq ($Role -join ',') -and
        ($_.Permissions -join ',') -ieq ($Permission -join ',')
    })

    if ($null -eq $check) {
        return
    }

    # remove the auth
    $auth = Get-IISMFtpAuthorizationCommandString -AccessType $AccessType -Permission $Permission -User $User -Role $Role
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/authorization /-`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMDirectoryFtpAuthorization -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Get-IISMDirectoryFtpIPSecurity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    return (Get-IISMDirectoryFtpIPSecurityInternal -Name $Name)
}

function Add-IISMDirectoryFtpIPSecurity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [string]
        $IPAddress,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubnetMask = '255.255.255.255',

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it already has the auth
    $current = (Get-IISMDirectoryFtpIPSecurityInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.IPAddress -ieq $IPAddress) -and
        ($_.SubnetMask -ieq $SubnetMask)
    })

    if ($null -ne $check) {
        Write-Verbose "IP Security already exists"
        return
    }

    # add the auth
    $auth = Get-IISMFtpIPSecurityCommandString -AccessType $AccessType -IPAddress $IPAddress -SubnetMask $SubnetMask
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/ipSecurity /+`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMDirectoryFtpIPSecurity -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Remove-IISMDirectoryFtpIPSecurity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType,

        [Parameter(Mandatory=$true)]
        [string]
        $IPAddress,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubnetMask = '255.255.255.255',

        [switch]
        $NoOutput
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # skip if it doesnt have the auth
    $current = (Get-IISMDirectoryFtpIPSecurityInternal -Name $Name).Rules
    $check = ($current | Where-Object {
        ($_.AccessType -ieq $AccessType) -and
        ($_.IPAddress -ieq $IPAddress) -and
        ($_.SubnetMask -ieq $SubnetMask)
    })

    if ($null -eq $check) {
        Write-Verbose "IP Security rule not found"
        return
    }

    # remove the auth
    $auth = Get-IISMFtpIPSecurityCommandString -AccessType $AccessType -IPAddress $IPAddress -SubnetMask $SubnetMask
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/ipSecurity /-`"$($auth)`" /commit:apphost" -NoParse | Out-Null

    if (!$NoOutput) {
        return (Get-IISMDirectoryFtpIPSecurity -SiteName $SiteName -AppName $AppName -DirName $DirName)
    }
}

function Set-IISMDirectoryFtpIPSecurityUnlisted
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $SiteName,

        [Parameter()]
        [string]
        $AppName = '/',

        [Parameter()]
        [string]
        $DirName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]
        $AccessType
    )

    # error if not ftp site
    if (!(Test-IISMSiteIsFtp -Name $SiteName)) {
        throw "Website '$($SiteName)' is not an FTP site"
    }

    $AppName = Add-IISMSlash -Value $AppName

    $Name = Add-IISMSlash -Value "$($SiteName)$($AppName)" -Append
    if (![string]::IsNullOrWhiteSpace($DirName)) {
        $Name = "$($Name)$($DirName)"
    }

    # error if the directory doesn't exist
    if (!(Test-IISMDirectory -SiteName $SiteName -AppName $AppName -DirName $DirName)) {
        throw "Directory '$($Name)' does not exist in IIS"
    }

    # set unlisted type
    $allow = ($AccessType -ieq 'Allow')
    Invoke-IISMAppCommand -Arguments "set config '$($Name)' /section:system.ftpServer/security/ipSecurity /allowUnlisted:'$($allow)' /commit:apphost" -NoParse | Out-Null
}