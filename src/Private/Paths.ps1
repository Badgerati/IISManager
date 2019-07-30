function Get-IISMHomePath
{
    if (Test-IsUnix) {
        return "/mnt/c/Windows/System32"
    }
    else {
        return "$($env:SystemDrive)/Windows/System32"
    }
}

function Get-IISMAppCmdPath
{
    return (Join-Path (Get-IISMHomePath) (Join-Path 'inetsrv' 'appcmd.exe'))
}

function Get-IISMNetshPath
{
    return (Join-Path (Get-IISMHomePath) 'netsh.exe')
}

function Get-IISMNetPath
{
    return (Join-Path (Get-IISMHomePath) 'net.exe')
}

function Get-IISMResetPath
{
    return (Join-Path (Get-IISMHomePath) 'iisreset.exe')
}

function Get-IISMSiteDefaultLogPath
{
    return "$($env:SystemDrive)/inetpub/logs/LogFiles"
}

function Get-IISMSiteDefaultLogFields
{
    $fields = @(
        'Date',
        'Time',
        'ServerIP',
        'Method',
        'UriStem',
        'UriQuery',
        'ServerPort',
        'UserName',
        'ClientIP',
        'UserAgent',
        'Referer',
        'HttpStatus',
        'HttpSubStatus',
        'TimeTaken'
    )

    return ($fields -join ',')
}