function Get-TimeStamp {
    return Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
}