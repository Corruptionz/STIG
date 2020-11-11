function Test-RegistryValue {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        # Check if Registry Key exists
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}