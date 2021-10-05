## Solution Guide: Generating Windows Event Log Files with Parameters and Pipelines

In this activity, you were responsible for retrieving recent security and application logs using PowerShell, transforming them to JSON, and then saving them to `C:\Logs`.

#### Solutions

1. First we need to check the names of the logs we want to retrieve:

   - Run `Get-WinEvent -listlog *` to show all log names.

2. Check for and retrieve the names of the security and application logs:

    - Scroll to the top to show the `Security` and `Application` log names in the `LogName` column.

    - Note the column header `LogName`. This header is also the parameter we need.

3. Let's add parameters to our cmdlet to retrieve security logs:

    - Run `Get-WinEvent -LogName Security -MaxEvents 100` to show only 100 events.

    - Add the `ConvertTo-Json` cmdlet to convert the output to JSON format:

      - Run `Get-WinEvent -LogName Security -MaxEvents 100 | ConvertTo-Json`

    - Pipe that output to a file:

      - Run `Get-WinEvent -LogName Security -MaxEvents 100 | ConvertTo-Json | Out-File -FilePath "C:\Logs\RecentSecurityLogs.json"`

    Since we didn't see any confirmation output, let's check the contents of the logs:

    - Run `Get-Content C:\Logs\RecentSecurityLogs.json` to confirm the logs were created.

    To get the latest 100 events from the application logs, run:

    - `Get-WinEvent -LogName Application -MaxEvents 100 | ConvertTo-Json | Out-File -FilePath "C:\Logs\RecentApplicationLogs.json"`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
