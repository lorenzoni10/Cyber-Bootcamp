$csv = Import-Csv -Path .\useremails.csv
foreach ($line in $csv) {
    echo $line.email
}