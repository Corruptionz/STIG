# ===========================================================================
# Author: Corruptz
# Creation Date : 11/30/2020
# Last Updated  : 12/2/2020
# ===========================================================================
# Description: 
# The Windows 10 Security Technical Implementation Guide (STIG) 
# is published as a tool to improve the security of Department of Defense (DoD) 
# information systems. 
# 
# This tool will check Windows 10 for and to fix any misconfigured / missing 
# registry keys according to the STIG documentation and implementations found at:
#                   https://stigviewer.com/stig/windows_10/.
# ===========================================================================
# READ ME
# ===========================================================================
# Script must be run in PowerShell with Administrative privileges and must 
# have 'Set-ExecutionPolicy RemoteSigned' enabled.
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

$status = ''

function Test-RegistryValue {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$ValueName,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    # Check if Registry Key exists
    if(Test-Path $Path) {
        # If Registry Key exists, get the Registry Key
        $registry_key = Get-Item $Path

        # Check if the Registry Key's value exists
        if($null -ne $registry_key.getValue($ValueName)) {
            # Registry Key value found. Get the value.
            $registry_key_value = Get-ItemProperty -Path $Path -Name $ValueName | Select-Object -exp $ValueName

            # Check if the value is configured properly
            if($registry_key_value -eq $Value) {
                # If the value is configured properly, STIG found not vulnerable
                $status = 0
                return $status
            } else {
                # If the value is misconfigured, STIG found misconfigured / vulnerable
                $status = 1
                return $status
            }
        } else {
            # Registry Key found, but value does not exist
            $status = 2
            return $status
        }
    } else {
        # Registry Key does not exist
        $status = 2
        return $status
    }
}

# USAGE: 
# Test-RegistryValue -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -ValueName 'NoLMHash' -Value '1'
# Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'fAllowToGetHelp' -Value '0'