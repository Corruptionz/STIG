# ===========================================================================
# Author: Corruptz
# Creation Date : 11/8/2020
# Last Updated  : 1/5/2021
# ===========================================================================
# Description: 
# The Windows 10 Security Technical Implementation Guide (STIG) 
# is published as a tool to improve the security of Department of Defense (DoD) 
# information systems. 
# 
# This tool will check Windows 10 for and to fix any misconfigured / missing 
# registry keys according to the STIG documentation and implementations found at:
#                   https://stigviewer.com/stig/windows_10/.
# ===========================================================================
# READ ME
# ===========================================================================
# Script must be run in PowerShell with Administrative privileges and must 
# have 'Set-ExecutionPolicy RemoteSigned' enabled to run scripts.
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# 2 = STIG not found and vulnerable
# ===========================================================================

# Include Get-TimeStamp
. 'functions\Get-TimeStamp.ps1'

# Begin script
Write-Host "====================================================================================="
Write-Host "[$(Get-TimeStamp)] Beginning Windows 10 STIG scan..."

# Define paths to check
$severity_high_path = "findings\severity\a_high\"
$severity_medium_path = "findings\severity\b_medium\"
$severity_low_path = "findings\severity\c_low\"

# Check high severity implementations
Write-Host "[$(Get-TimeStamp)] Starting scan for CAT I (High Severity) STIGs..."

# Define empty arrays and counts
$high_severity_files_checked = @()
$high_severity_files_checked_count = 0

$high_severity_findings_safe = @()
$high_severity_findings_safe_count = 0

$high_severity_findings_misconfigured = @()
$high_severity_findings_misconfigured_count = 0

$high_severity_findings_missing = @()
$high_severity_findings_missing_count = 0

# Execute high severity child implementations
foreach ($file in Get-ChildItem $severity_high_path -Filter *.ps1) {
    # Get file name, add to files checked array
    $file_name = $file.Name
    $file_name = $file_name -replace '.ps1', ''
    $high_severity_files_checked += $file_name    

    # Increment counter
    $high_severity_files_checked_count++

    # Execute script
    Write-Host "[$(Get-TimeStamp)] Executing scan for CAT I Finding ID: $file_name..."
    $execute = &"findings\severity\a_high\$file_name.ps1"
    
    # Check status of script
    $status = $execute

    if ($status -eq 0) {
        # 0 = STIG found not vulnerable
        $high_severity_findings_safe += $file_name
        $high_severity_findings_safe_count++
        continue
    } elseif ($status -eq 1) {
        # 1 = STIG found misconfigured / vulnerable
        $high_severity_findings_misconfigured += $file_name
        $high_severity_findings_misconfigured_count++
        continue
    } else {
        # 2 = STIG not found and vulnerable
        $high_severity_findings_missing += $file_name
        $high_severity_findings_missing_count++
        continue
    }
}

# Report
Write-Host "[$(Get-TimeStamp)] Scan Complete."
Write-Host "====================================================================================="
Write-Host ""

$results = @(
    [PSCustomObject]@{
        Severity = "CAT I (High)"
        Total = 26
        Checked = $high_severity_files_checked_count
        Secure = $high_severity_findings_safe_count
        Vulnerable = $high_severity_findings_misconfigured_count
    },
    [PSCustomObject]@{
        Severity = "CAT II (Medium)"
        Total = 246
        Checked = 0
        Secure = 0
        Vulnerable = 0
    },
    [PSCustomObject]@{
        Severity = "CAT III (Low)"
        Total = 18
        Checked = 0
        Secure = 0
        Vulnerable = 0
    }
)

$results | Format-Table -AutoSize | Out-String | ForEach-Object {$_.Trim()}

Write-Host ""
Write-Host "There were [$high_severity_findings_safe_count] CAT I (High) STIGs found with secure configurations. "
if ($high_severity_findings_safe_count -gt 0) {
    foreach ($item in $high_severity_findings_safe) {
        Write-Host $item
    }
}
Write-Host ""
Write-Host "There were [0] CAT II (Medium) STIGs found with secure configurations. "
Write-Host ""
Write-Host "There were [0] CAT III (Low) STIGs found with secure configurations. "
Write-Host ""
Write-Host "There were [$high_severity_findings_misconfigured_count] CAT I (High) STIGs found with vulnerable configurations."
if ($high_severity_findings_misconfigured_count -gt 0) {
    foreach ($item in $high_severity_findings_misconfigured) {
        Write-Host $item
    }
}
Write-Host ""
Write-Host "There were [0] CAT II (Medium) STIGs found with vulnerable configurations."
Write-Host ""
Write-Host "There were [0] CAT III (Low) STIGs found with vulnerable configurations."
Write-Host ""
Write-Host "====================================================================================="

# gpupdate /force