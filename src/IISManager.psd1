#
# Module manifest for module 'IISManager'
#
# Generated by: Matthew Kelly (Badgerati)
#
# Generated on: 03/06/2019
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'IISManager.psm1'

    # Version number of this module.
    ModuleVersion = '2.1.1'

    # ID used to uniquely identify this module
    GUID = 'a3ba417c-dc1d-446b-95a5-a306ab26c1af'

    # Author of this module
    Author = 'Matthew Kelly (Badgerati)'

    # Copyright statement for this module
    Copyright = 'Copyright (c) 2019 Matthew Kelly (Badgerati), licensed under the MIT License.'

    # Description of the functionality provided by this module
    Description = 'PowerShell module to manage IIS, that also supports working in PowerShell Core'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '3.0'

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('powershell', 'web', 'server', 'websites', 'powershell-core', 'windows', 'PSEdition_Core',
                'iis', 'management', 'administration', 'certificates', 'netsh', 'net', 'appcmd', 'ftp')

            # A URL to the license for this module.
            LicenseUri = 'https://raw.githubusercontent.com/Badgerati/IISManager/master/LICENSE.txt'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/Badgerati/IISManager'

        }
    }
}