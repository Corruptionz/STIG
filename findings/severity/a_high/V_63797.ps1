# ===========================================================================
# Author: Corruptz
# Creation Date : 12/1/2020
# Last Updated  : 12/2/2020
# ===========================================================================
# Title       : The system must be configured to prevent the storage of the LAN 
#               Manager hash of passwords.
# Finding ID  : V-63797
# Version     : WN10-SO-000195
# Rule ID     : SV-78287r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://stigviewer.com/stig/windows_10/2020-03-24/finding/V-63797
# ===========================================================================
# Description: 
# The LAN Manager has uses a weak encryption alorithm and there are 
# several tools available that use this hash to retrieve account passwords.
# This setting controls whether or not a LAN Manager has of the password
# is stored in the SAM the next time the password is changed. 
# ===========================================================================
# Check Text ( C-64547r1_chk )
# If the following registry value does not exist or is not configured as 
# specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: NoLMHash
#
# Value Type: REG_DWORD
# Value: 1 
# ===========================================================================
# Fix Text:
# (F-69725r1_fix)
# Configure the policy value for Computer Configuration >> Windows Settings 
# >> Security Settings >> Local Policies >> Security Options >> "Network 
# security: Do not store LAN Manager hash value on next password change" to 
# "Enabled". 
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Test-RegistryValue
. 'C:\Users\Win_10_STIG\Documents\STIG\STIG\functions\Test-RegistryValue.ps1'

$V_63797 = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'NoLMHash' -Value '1'

$status = ''

if($V_63797 -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"
    $status = 0
    return $status

} elseif($V_63797 -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'NoLmHash' -Type 'DWORD' -Value '1' -Force

    $status = 1
    return $status
    
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'NoLmHash' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 2
    return $status
}
