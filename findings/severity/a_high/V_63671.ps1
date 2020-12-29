# ====================================================================================================
# Author: Corruptz
# Creation Date : 12/29/2020
# Last Updated  : 12/29/2020
# ====================================================================================================
# Title       : The default autorun behavior must be configured to prevent autorun commands.
# Finding ID  : V-63671
# Version     : WN10-CC-000185
# Rule ID     : SV-78161r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63671
# ====================================================================================================
# Description: 
# Allowing autorun commands to execute may introduce malicious code to a system. Configuring this 
# setting prevents autorun commands from executing. 
# ====================================================================================================
# Check Text ( C-64419r1_chk  )
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\
#
# Value Name: NoAutorun
#
# Value Type: REG_DWORD
# Value: 1
# ====================================================================================================
# Fix Text (F-69599r1_fix)
# Configure the policy value for Computer Configuration >> Administrative Templates 
# >> Windows Components >> AutoPlay Policies >> "Set the default behavior for AutoRun" to 
# "Enabled:Do not execute any autorun commands". 
# ====================================================================================================
# RETURN STATUS KEY
# ====================================================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ====================================================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$STIG = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' -ValueName 'NoAutorun' -Value '1'

$status = ''

if($STIG -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($STIG -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' -Name 'NoAutorun' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' -Name 'NoAutorun' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 2
    return $status
}