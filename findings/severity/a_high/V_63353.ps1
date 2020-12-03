# ===========================================================================
# Author: Corruptz
# Creation Date : 12/3/2020
# Last Updated  : 12/3/2020
# ===========================================================================
# Title       : Local volumes must be formatted using NTFS.
# Finding ID  : V-63325
# Version     : WN10-00-000050
# Rule ID     : SV-77843r2_rule
# IA Controls : NULL
# Severity    : High
# Finding URL : https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63353
# ===========================================================================
# Description: 
# The ability to set access permissions and auditing is critical to maintaining 
# the security and proper access controls of a system. To support this, volumes 
# must be formatted using the NTFS file system. 
# ===========================================================================
# Check Text ( C-73999r1_chk )
# Run "Computer Management".
# Navigate to Storage >> Disk Management.
# 
# If the "File System" column does not indicate "NTFS" for each volume assigned 
# a drive letter, this is a finding.
# 
# This does not apply to system partitions such the Recovery and EFI System 
# Partition.
# ===========================================================================
# Fix Text (F-69273r1_fix)
#  Format all local volumes to use NTFS. 
# ===========================================================================
# RETURN STATUS KEY
# ===========================================================================
# 0 = STIG found not vulnerable
# 1 = STIG found misconfigured / vulnerable
# ===========================================================================

$status = 0

# Get all drives
[System.IO.DriveInfo]::GetDrives() | ForEach-Object {
    # Get drive information
    $drive_name = $_.Name
    $drive_type = $_.DriveType
    $drive_format = $_.DriveFormat
    $volume_label = $_.VolumeLabel

    # Only Format local drives
    if($drive_type -eq 'Fixed') {
        if($drive_format -ne 'NTFS') {
            # Remove backslash from $drive_name
            $drive_name = $drive_name -replace '\\',''

            # If drive is not NTFS, convert it.  
            $volume_label | convert $drive_name /fs:ntfs | Out-Null

            $status = 1
        }
    }    
}

return $status