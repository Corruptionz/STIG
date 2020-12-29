# ====================================================================================================
# Author: Corruptz
# Creation Date : 12/29/2020
# Last Updated  : 12/29/2020
# ====================================================================================================
# Title       : Internet Information System (IIS) or its subcomponents must not be installed on a workstation.
# Finding ID  : V-63377
# Version     : WN10-00-000100
# Rule ID     : SV-77867r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63377
# ====================================================================================================
# Description: 
# Installation of Internet Information System (IIS) may allow unauthorized internet services to be 
# hosted. Websites must only be hosted on servers that have been designed for that purpose and can be 
# adequately secured. 
# ====================================================================================================
# Check Text (C-64117r1_chk)
# IIS is not installed by default. Verify it has not been installed on the system.
# 
# Run "Programs and Features".
# Select "Turn Windows features on or off".
# 
# If the entries for "Internet Information Services" or "Internet Information Services Hostable Web 
# Core" are selected, this is a finding.
# 
# If an application requires IIS or a subset to be installed to function, this needs be documented 
# with the ISSO. In addition, any applicable requirements from the IIS STIG must be addressed.
# ====================================================================================================
# Fix Text (F-69297r1_fix)
# Uninstall "Internet Information Services" or "Internet Information Services Hostable Web Core" 
# from the system. 
# ====================================================================================================
# RETURN STATUS KEY
# ====================================================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# ====================================================================================================

$status = ''

$IIS_WebServer_Enabled = $null
$IIS_WebServerRole_Enabled = $null

# Check if IIS Web Server state is enabled
if ((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer").State -eq "Enabled") {
    $IIS_WebServer_Enabled = $true
} else {
    $IIS_WebServer_Enabled = $false
}

# Check if IIS Web Server Role state is enabled
if ((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole").State -eq "Enabled") {
    $IIS_WebServerRole_Enabled = $true
} else {
    $IIS_WebServerRole_Enabled = $false
}

# If either are enabled, remove the features. A reboot will be required.
if (($IIS_WebServer_Enabled -eq $true) -or ($IIS_WebServerRole_Enabled -eq $true)) {

    $WarningPreference = "SilentlyContinue"
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -NoRestart | Out-Null 
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart | Out-Null 
    $WarningPreference = "Continue"

    $status = 1
    return $status

} else {
    $status = 0
    return $status
}