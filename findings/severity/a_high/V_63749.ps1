# ===========================================================================
# Author: Corruptz
# Creation Date : 12/7/2020
# Last Updated  : 12/7/2020
# ===========================================================================
# Title       : Anonymous enumeration of shares must be restricted.
# Finding ID  : V-63749
# Version     : WN10-SO-000150
# Rule ID     : SV-78239r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63759
# ===========================================================================
# Description: 
# Allowing anonymous logon users (null session connections) to list all 
# account names and enumerate all shared resources can provide a map of 
# potential points to attack the system. 
# ===========================================================================
# Check Text ( C-64499r1_chk )
# If the following registry value does not exist or is not configured as 
# specified, this is a finding:
# 
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: RestrictAnonymous
# 
# Value Type: REG_DWORD
# Value: 1 
# ===========================================================================
# Fix Text (F-69687r1_fix)
# Configure the policy value for Computer Configuration >> Windows Settings 
# >> Security Settings >> Local Policies >> Security Options >> "Network 
# access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$STIG = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ValueName 'RestrictAnonymous' -Value '1'

$status = ''

if($STIG -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($STIG -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -Name 'RestrictAnonymous' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -Name 'RestrictAnonymous' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 2
    return $status
}