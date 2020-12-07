# ===========================================================================
# Author: Corruptz
# Creation Date : 12/7/2020
# Last Updated  : 12/7/2020
# ===========================================================================
# Title       : Anonymous access to Named Pipes and Shares must be restricted.
# Finding ID  : V-63759
# Version     : WN10-SO-000165
# Rule ID     : SV-78249r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63759
# ===========================================================================
# Description: 
# Allowing anonymous access to named pipes or shares provides the potential 
# for unauthorized system access.  This setting restricts access to those 
# defined in "Network access: Named Pipes that can be accessed anonymously" 
# and "Network access: Shares that can be accessed anonymously",  both of 
# which must be blank under other requirements.
# ===========================================================================
# Check Text ( C-64509r1_chk )
# If the following registry value does not exist or is not configured as 
# specified, this is a finding:
# 
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\
#
# Value Name: RestrictNullSessAccess
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

$STIG = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -ValueName 'RestrictNullSessAccess' -Value '1'

$status = ''

if($STIG -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($STIG -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -Name 'RestrictNullSessAccess' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value

    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -Name 'RestrictNullSessAccess' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 2
    return $status
}