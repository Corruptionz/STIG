# ===========================================================================
# Author: Corruptz
# Creation Date : 11/8/2020
# Last Updated  : 11/11/2020
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
# have 'Set-ExecutionPolicy RemoteSigned' enabled.
# ===========================================================================

# Include Get-TimeStamp
. 'functions\Get-TimeStamp.ps1'

# Begin script
Write-Host "[$(Get-TimeStamp)] Checking Windows 10 security implementations ..."

# Define paths to check
$severity_high_path = "findings\severity\a_high\"
$severity_medium_path = "findings\severity\b_medium\"
$severity_low_path = "findings\severity\c_low\"

# Check high severity implementations
Write-Host "[$(Get-TimeStamp)] Checking high severity implementations ..."

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
    $high_severity_files_checked += $file_name    

    # Increment counter
    $high_severity_files_checked_count++

    # Execute script
    Write-Host "[$(Get-TimeStamp)] Executing $file_name..."
    $execute = &"findings\severity\a_high\$file_name"
    
    # Check status of script
    $status = $execute

    if ($status -eq 0) {
        # Security implementation found / verified correct
        $high_severity_findings_safe += $file_name
        $high_severity_findings_safe_count++
        continue

    } elseif ($status -eq 1) {
        # Security implementation found, however misconfigured
        $high_severity_findings_misconfigured += $file_name
        $high_severity_findings_misconfigured_count++
        continue

    } else {
        # Security implementation not found / missing
        $high_severity_findings_missing += $file_name
        $high_severity_findings_missing_count++
        continue
    }
}

# Report
Write-Host "[$(Get-TimeStamp)] Report finished ..."
Write-Host "==========================================================================="
Write-Host "Count of high severity implementations checked: $high_severity_files_checked_count"

if ($high_severity_files_checked_count -gt 0) {
    Write-Host "All implementations checked: "
}

foreach ($item in $high_severity_files_checked) {
    Write-Host $item
}

Write-Host "==========================================================================="
Write-Host "Count of high severity safe implementations: $high_severity_findings_safe_count"

if ($high_severity_findings_safe_count -gt 0) {
    Write-Host "Safe implementations found: "
}

foreach ($item in $high_severity_findings_safe) {
    Write-Host $item
}

Write-Host "==========================================================================="
Write-Host "Count of high severity misconfigured implementations: $high_severity_findings_misconfigured_count"

if ($high_severity_findings_misconfigured_count -gt 0) {
    Write-Host "Misconfigurations found: "
}

foreach ($item in $high_severity_findings_misconfigured) {
    Write-Host $item
}

Write-Host "==========================================================================="
Write-Host "Count of high severity missing implementations: $high_severity_findings_missing_count"

if ($high_severity_findings_missing_count -gt 0) {
    Write-Host "Missing implementations found: " 
}

foreach ($item in $high_severity_findings_missing) {
    Write-Host $item
}

Write-Host "==========================================================================="

# Reboot? 