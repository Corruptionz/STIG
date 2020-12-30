# ====================================================================================================
# Author: Corruptz
# Creation Date : 12/29/2020
# Last Updated  : 12/29/2020
# ====================================================================================================
# Title       : The Act as part of the operating system user right must not be assigned to any groups 
#               or accounts.
# Finding ID  : V-63847
# Version     : WN10-UR-000015
# Rule ID     : SV-78337r1_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63847
# ====================================================================================================
# Description: 
# Inappropriate granting of user rights can provide system, administrative, and other high level 
# capabilities. Accounts with the "Act as part of the operating system" user right can assume the 
# identity of any user and gain access to resources that user is authorized to access. Any accounts 
# with this right can take complete control of a system. 
# ====================================================================================================
# Check Text (C-64597r1_chk)
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
# 
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings 
# >> Local Policies >> User Rights Assignment. 
# 
# If any groups or accounts (to include administrators), are granted the "Act as part of the operating 
# system" user right, this is a finding. 
# ====================================================================================================
# Fix Text (F-69775r1_fix)
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> 
# Local Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but 
# containing no entries (blank). 
# ====================================================================================================
# RETURN STATUS KEY
# ====================================================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# ====================================================================================================

# Get AppData path
$path = $env:WINDIR+'\System32\GroupPolicy\TempLocalSecurityPolicy.cfg'

# Export local security policy
secedit /export /cfg $path | Out-Null

# Get contents of original local security policy
$config_orig = Get-Content($path)

# Set status = 0 to assume the value is 'missing'
$status = '0'

# Check each line for SeTcbPrivilege regex
foreach ($line in $config_orig) {
    # Misconfigured
    if ($line -match 'SeTcbPrivilege = .*.') {
        $status = 1
        break
    } 
}

if($status -eq 0) {
    # Local security policy is correct, do nothing 
} elseif ($status -eq 1) {
    # Misconfiguration, clear local security policy user right
    (Get-Content -path $path -Raw) -replace 'SeTcbPrivilege = .*.', 'SeTcbPrivilege = ' | Set-Content -path $path
    (Get-Content $path) -match '\S' | Set-Content -path $path
}

# Update local security policy
secedit /configure /db C:\Windows\Security\Local.sdb /cfg $path | Out-Null

# Delete configuration file
Remove-Item -Force $path -confirm:$false 

return $status