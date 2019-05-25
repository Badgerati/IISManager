function Get-IISMDirectories
{
    param (
        [Parameter()]
        [string]
        $Name
    )

    if (![string]::IsNullOrWhiteSpace($Name)) {
        $result = Invoke-IISMAppCommand -Arguments "list vdir '$($Name)'"
    }
    else {
        $result = Invoke-IISMAppCommand -Arguments 'list vdirs'
    }

    if ($null -eq $result) {
        return $null
    }

    ConvertTo-IISMDirectoryObject -Directories $result.VDIR
}

function Test-IISMDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($null -ne (Get-IISMDirectories -Name $Name))
}

function Remove-IISMDirectory
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    if (!(Test-IISMDirectory -Name $Name)) {
        return
    }

    Invoke-IISMAppCommand -Arguments "delete vdir '$($Name)'" -NoParse | Out-Null
    return (Get-IISMDirectories)
}

#TODO: create vdir?
#TODO: modify vdir?