$csv = Import-Csv -Path .\chocoactivity.csv
foreach ($line in $csv) {
    choco uninstall -y $line.name
    Write-Output $line.name removed!
}