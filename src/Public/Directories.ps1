function Get-IISDirectories
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISAppCommand -Arguments "list vdir '$($Name)'"
    }
    else {
        $result = Invoke-IISAppCommand -Arguments 'list vdirs'
    }

    if ($null -eq $result) {
        return $null
    }

    ConvertTo-IISDirectoryObject -Directories $result.VDIR
}

function Test-IISDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISDirectories -Name $Name))
}

function Remove-IISDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISDirectory -Name $Name)) {
        return
    }

    Invoke-IISAppCommand -Arguments "delete vdir '$($Name)'" -NoParse | Out-Null
}