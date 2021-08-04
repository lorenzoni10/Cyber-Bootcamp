$csv = Import-Csv -Path .\chocoactivity.csv
foreach ($package in $csv) {
    choco uninstall -y $package.name
    Write-Output $package.name removed!
}