## Activity File: Generating Windows Event Log Files with Parameters and Pipelines

In this activity, you will play the role of a Windows system administrator. 

- You are tasked with creating and saving logs to the directory `C:\Logs`.

- These logs can then be sent to security analysts for examination in a Security Information and Event Management System (SIEM). 

Continue to use the Windows RDP Host machine for this activity. 

### Instructions

Your CIO has tasked you to do the following in PowerShell:

1. Use `Get-WinEvent -listlog *` to show the list of available logs.

2. Check for and retrieve the names of the security and application logs.

3. For each of the above logs, create a pipeline that:

    - Gets the latest 100 events.

    - Transforms the log to JSON.

    - Outputs the objects in the JSON file to the `C:\Logs` directory.

Hint: To complete this activity, you will need to use the `Get-WinEvent`, `ConvertTo-Json`, and `Out-File` cmdlets.

- At the end of this activity, the following files should be in `C:\Logs`:

    - `RecentSecurityLogs.json`
    - `RecentApplicationLogs.json`

- This means you'll need to run the PowerShell pipeline at least two times.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
