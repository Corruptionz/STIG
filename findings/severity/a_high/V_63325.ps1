# ===========================================================================
# Author: Corruptz
# Creation Date : 12/2/2020
# Last Updated  : 12/7/2020
# ===========================================================================
# Title       : The Windows Installer Always install with elevated privileges 
#               must be disabled.
# Finding ID  : V-63325
# Version     : WN10-CC-000315
# Rule ID     : SV-77815r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63325
# ===========================================================================
# Description: 
# Standard user accounts must not be granted elevated privileges.  Enabling 
# Windows Installer to elevate privileges when installing applications can 
# allow malicious persons and applications to gain full control of a system.
# ===========================================================================
# Check Text ( C-64059r1_chk )
# If the following registry value does not exist or is not configured as 
# specified, this is a finding:
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
# Configure the policy value for Computer Configuration >> Administrative 
# Templates >> Windows Components >> Windows Installer >> "Always install 
# with elevated privileges" to "Disabled".
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$STIG = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\' -ValueName 'AlwaysInstallElevated' -Value '0'

$status = ''

if($STIG -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($STIG -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\' -Name 'AlwaysInstallElevated' -Type 'DWORD' -Value '0' -Force | Out-Null

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Installer' -Force | Out-Null
    New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\' -Name 'AlwaysInstallElevated' -Type 'DWORD' -Value '0' -Force | Out-Null

    $status = 2
    return $status
}