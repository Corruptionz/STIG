# ===========================================================================
# Author: Corruptz
# Creation Date : 12/3/2020
# Last Updated  : 12/3/2020
# ===========================================================================
# Title       : Autoplay must be turned off for non-volume devices.
# Finding ID  : V-63667
# Version     : WN10-CC-000180
# Rule ID     : SV-78157r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63325
# ===========================================================================
# Description: 
# Allowing autoplay to execute may introduce malicious code to a system. 
# Autoplay begins reading from a drive as soon as you insert media in the 
# drive. As a result, the setup file of programs or music on audio media may 
# start. This setting will disable autoplay for non-volume devices (such as 
# Media Transfer Protocol (MTP) devices). 
# ===========================================================================
# Check Text ( C-64415r1_chk )
# If the following registry value does not exist or is not configured as specified, this is a finding:
# 
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\
# 
# Value Name: NoAutoplayfornonVolume
#
# Value Type: REG_DWORD
# Value: 1 
# ===========================================================================
# Fix Text (F-69595r1_fix)
# Configure the policy value for Computer Configuration >> Administrative 
# Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay 
# for non-volume devices" to "Enabled". 
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$V_63651 = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\' -ValueName 'NoAutoplayfornonVolume' -Value '1'

$status = ''

if($V_63651 -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($V_63651 -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\' -Name 'NoAutoplayfornonVolume' -Type 'DWORD' -Value '1' -Force

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Explorer' -Force | Out-Null
    New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\' -Name 'NoAutoplayfornonVolume' -Type 'DWORD' -Value '1' -Force | Out-Null

    $status = 2
    return $status
}