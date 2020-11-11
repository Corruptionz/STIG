# ===========================================================================
# Author: Corruptz
# Creation Date : 11/8/2020
# Last Updated  : 11/11/2020
# ===========================================================================
# Title       : The Debug programs user right must only be assigned to the 
#               Administrators group.
# Finding ID  : V-63869
# Version     : WN10-UR-000065
# Rule ID     : SV-78359r1_rule
# IA Controls : NULL 
# Severity    : High
# Finding URL : https://stigviewer.com/stig/windows_10/2020-03-24/finding/V-63869
# ===========================================================================
# Description: 
# Inappropriate granting of user rights can provide system, administrative, 
# and other high level capabilities. Accounts with the "Debug Programs" user 
# right can attach a debugger to any process or to the kernel, providing complete 
# access to sensitive and critical operating system components. This right is 
# given to Administrators in the default configuration. 
# ===========================================================================
# Details: 
# Check Text ( C-64619r1_chk )
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
# 
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings 
# >> Security Settings >> Local Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Debug 
# Programs" user right, this is a finding:
# 
# Administrators 
# ===========================================================================
# Fix Text: 
# Fix Text (F-69797r1_fix)
# Configure the policy value for Computer Configuration >> Windows Settings 
# >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug 
# programs" to only include the following groups or accounts:
# 
# Administrators 
# ===========================================================================

# Get AppData path
$path = $env:LOCALAPPDATA+"\Temp\LocalSecurityPolicy.cfg"

# Export local security policy
secedit /export /cfg $path | Out-Null

# Get contents of original local security policy
$config_orig = Get-Content($path)

# Set status = 2 to assume the value is 'missing'
$status = '2'

# Check each line for SeDebugPrivilige regex
foreach ($line in $config_orig) {
    # Misconfigured
    if ($line -match 'SeDebugPrivilege = .*\,.*') {
        $status = 1
        break
    } 

    # Configured properly
    if ($line -match 'SeDebugPrivilege = \*S-1-5-32-544') {
        $status = 0
        break
    } 
}

if($status -eq 0) {
    # local security policy is correct, do nothing 
} elseif ($status -eq 1) {
    # Misconfiguration, set local security policy to Administrators only
    (Get-Content -path $path -Raw) -replace 'SeDebugPrivilege = .*\,.*', 'SeDebugPrivilege = *S-1-5-32-544' | Set-Content -path $path
} else {
    # Missing, add SeDebugPrivilege to end of local security policy
    (Get-Content -path $path -Raw) -replace '\[Version\]', 'SeDebugPrivilege = *S-1-5-32-544
[Version]' | Set-Content -path $path 
}

# Update local security policy
secedit /configure /db C:\Windows\Security\Local.sdb /cfg $path | Out-Null

# Delete configuration file
Remove-Item -Force $path -confirm:$false 

return $status