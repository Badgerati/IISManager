function Get-IISHomePath
{
    if (Test-IsUnix) {
        return "/mnt/c/Windows/System32"
    }
    else {
        return "$($env:SystemDrive)/Windows/System32"
    }
}

function Get-IISAppCmdPath
{
    return (Join-Path (Get-IISHomePath) (Join-Path 'inetsrv' 'appcmd.exe'))
}

function Get-IISNetshPath
{
    return (Join-Path (Get-IISHomePath) 'netsh.exe')
}