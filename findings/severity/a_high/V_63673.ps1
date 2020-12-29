# ===========================================================================
# Author: Corruptz
# Creation Date : 12/29/2020
# Last Updated  : 12/29/2020
# ===========================================================================
# Title       : Autoplay must be disabled for all drives.
# Finding ID  : V-63673
# Version     : WN10-CC-000190
# Rule ID     : SV-78163r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63673
# ===========================================================================
# Description: 
# Allowing autoplay to execute may introduce malicious code to a system. 
# Autoplay begins reading from a drive as soon as you insert media in the 
# drive. As a result, the setup file of programs or music on audio media may 
# start. By default, autoplay is disabled on removable drives, such as the 
# floppy disk drive (but not the CD-ROM drive) and on network drives. 
# If you enable this policy, you can also disable autoplay on all drives. 
# ===========================================================================
# Check Text ( C-64423r1_chk )
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\
#
# Value Name: NoDriveTypeAutoRun
#
# Value Type: REG_DWORD
# Value: 0x000000ff (255)
# 
# Note: If the value for NoDriveTypeAutorun is entered manually, it must be 
# entered as "ff" when Hexadecimal is selected, or "255" with Decimal 
# selected. Using the policy value specified in the Fix section will enter 
# it correctly. 
# ===========================================================================
# Fix Text (F-69603r1_fix)
# Configure the policy value for Computer Configuration >>
# Administrative Templates >> Windows Components >> AutoPlay Policies 
# >> "Turn off AutoPlay" to "Enabled:All Drives". 
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Test-RegistryValue
. '.\functions\Test-RegistryValue.ps1'

$STIG = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' -ValueName 'NoDriveTypeAutoRun' -Value '0x000000ff'

$status = ''

if($STIG -eq 0) {
    # Write-Host "0 = STIG found not vulnerable"

    $status = 0
    return $status

} elseif($STIG -eq 1) {
    # Write-Host "1 = STIG found misconfigured / vulnerable"
    # Reconfigure Registry Key and Value
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' -Name 'NoDriveTypeAutoRun' -Type 'DWORD' -Value '0x000000ff' -Force | Out-Null

    $status = 1
    return $status
} else {
    # Write-Host "2 = STIG not found and vulnerable"
    # Add Registry Key and Value
    New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' -Name 'NoDriveTypeAutoRun' -Type 'DWORD' -Value '0x000000ff' -Force | Out-Null

    $status = 2
    return $status
}