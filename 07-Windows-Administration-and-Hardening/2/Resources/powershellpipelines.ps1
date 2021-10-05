`Get-WinEvent -ListLog *`

```PowerShell
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 100 | Sort-Object -Property TimeCreated -Descending | Select-Object -First 100 | ConvertTo-Html | Out-File -FilePath .\RecentPowerShellLogs.html
```

```PowerShell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 100 | Sort-Object -Property TimeCreated -Descending | Select-Object -First 100 | ConvertTo-Html | Out-File -FilePath .\RecentWindowsDefenderLogs.html
```

```PowerShell
Get-WinEvent -LogName "Security" -MaxEvents 100 | Sort-Object -Property TimeCreated -Descending | Select-Object -First 100 | ConvertTo-Html | Out-File -FilePath .\RecentSecurityLogs.html
```

```PowerShell
Get-EventLog -LogName "Windows PowerShell" -Newest 50 | Sort-Object -Property TimeGenerated -Descending | ConvertTo-Html | Out-File -FilePath .\RecentPowerShellLogs.html
```

```PowerShell
Get-EventLog -LogName Application -Newest 50 | Sort-Object -Property TimeGenerated -Descending | ConvertTo-Html | Out-File -FilePath .\RecentApplicationLogs.html
```

```PowerShell
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -Property DisplayName, DisplayVersion, InstallDate | Sort-Object -Property DisplayName
```