# ===========================================================================
# Author: Corruptz
# Creation Date : 11/8/2020
# Last Updated  : 12/2/2020
# ===========================================================================
# Title       : Solicited Remote Assistance must not be allowed.
# Finding ID  : V-63651
# Version     : WN10-CC-000155
# Rule ID     : SV-78141r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://stigviewer.com/stig/windows_10/2020-03-24/finding/V-63651
# ===========================================================================
# Description: 
# Remote assistance allows another user to view or take control of the local 
# session of a user. Solicited assistance is help that is specifically requested 
# by the local user. This may allow unauthorized parties access to the resources 
# on the computer. 
# ===========================================================================
# Check Text ( C-64401r1_chk )
# If the following registry value does not exist or is not configured as 
# specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fAllowToGetHelp
#
# Value Type: REG_DWORD
# Value: 0 
# ===========================================================================
# Fix Text: 
# (F-69581r1_fix)
# Configure the policy value for Computer Configuration >> Administrative 
# Templates >> System >> Remote Assistance >> "Configure Solicited Remote 
# Assistance" to "Disabled". 
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$V_63651 = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'fAllowToGetHelp' -Value '0'

$status = ''

if($V_63651 -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($V_63651 -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Type 'DWORD' -Value '0' -Force

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Type 'DWORD' -Value '0' -Force | Out-Null

    $status = 2
    return $status
}