# ===========================================================================
# Author: Corruptz
# Creation Date : 11/11/2020
# Last Updated  : 11/11/2020
# ===========================================================================
# Title       : The Windows Installer Always install with elevated privileges 
#               must be disabled.
# Finding ID  : V-63325
# Version     : WN10-CC-000315
# Rule ID     : SV-77815r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://stigviewer.com/stig/windows_10/2020-03-24/finding/V-63325
# ===========================================================================
# Description: 
# Standard user accounts must not be granted elevated privileges. Enabling Windows
# Installer to elevate privileges when installing applications can allow malicious 
# persons and applications to gain full control of a system. 
# ===========================================================================
# Details: 
# Check Text ( C-64059r1_chk )
# If the following registry value does not exist or is not configured as specified, 
# this is a finding:
# 
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\
# 
# Value Name: AlwaysInstallElevated
# 
# Value Type: REG_DWORD
# Value: 0 
# ===========================================================================
# Fix Text: 
# (F-69243r1_fix)
# Configure the policy value for Computer Configuration >> Administrative Templates 
# >> Windows Components >> Windows Installer >> "Always install with elevated 
# privileges" to "Disabled".  
# ===========================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\'

$V_63325 = Test-RegistryValue -Path $path -Value AlwaysInstallElevated

if ($V_63325 -eq $true) {
    $key_data = ""
    $key_data = Get-ItemProperty -Path $path -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    $key_data = $key_data.NoLmHash

    if ($key_data -eq 0) {
        # Mark as safe, add to report, move on
        $status = 0
        return $status
    } else {
        # Mark as unsafe, add to report, fix, and move on
        Set-ItemProperty -Path $path -Name AlwaysInstallElevated -Type DWORD -Value 0 -Force

        $status = 1
        return $status
    }
} else {
    # Mark as missing, add to report, add to registry, and move on
    New-ItemProperty $path -Name AlwaysInstallElevated -Type DWORD -Value 0 -Force >$null 2>&1

    $status = 2
    return $status
}

return $status