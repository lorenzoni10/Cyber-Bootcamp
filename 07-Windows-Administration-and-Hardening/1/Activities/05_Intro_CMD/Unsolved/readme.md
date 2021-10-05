## Activity File: Intro to Task Manager and CMD

In this activity, you play the role of a junior systems administrator at Good Corp, Inc.

- Throughout the day, you will be working on a report about this Windows machine. You will start the report in this activity.

- A senior software developer who recently left the company left behind a Windows workstation that was never centrally managed by IT. 

- Your CIO has requested that you do the following on the Windows workstation:

   - Use Task Manager to clean up running and startup processes.

   - Use CMD to create a simple text file in the `%USERPROFILE%\Desktop` directory called `report.txt` and begin appending Windows system information to it.

Make sure you're logged into the **Windows RDP Host Machine** with the following credentials:

- Username: `azadmin`
- Password: `p4ssw0rd*`

### Instructions 

1. Use Task Manager to end the following processes (tasks) if they are running:

   - Apple Push
   - iCloud Services
   - iPod Service
   - iTunesHelper
   - Skype
   - Apple Push
   - TeamViewer 

    **Note**: There may be multiple of these tasks, such as the Skype instances.

2. Use Task Manager to disable all startup processes, except for the following:

   -  Microsoft OneDrive
   -  Windows Security notification icon

3. Using the Windows command line, create a `reports` folder on the user's desktop where you'll store your findings.

   - **Note**: You'll likely want to save all of your working commands to a text file for reference. This way, if you mess up your report, you can delete it easily and re-run the working commands.

4.  Print a line that reads `Baselining Report` and output it to a new `report.txt` file. This will create a title within your report.

5. Print another line titled `Created by [your name here]` and append it to the file.


6. Use the ENV variables in the command line to add the following:

   - Add the OS, date, and user to the report using the command line.  Use the following format and refer to the reference table below: 
   
   - `[operating system] system report created on [today's date] with logged in user, [current username]`  

      | Environment Variable | Default Value          |
      | :------------------- | :--------------------- |
      | `%CD%`                 | Current directory      |
      | `%DATE%`               | Current date       |
      | `%OS%`                 | Windows                |
      |` %ProgramFiles%`     | `C:\Program Files`       |
      | `%ProgramFiles(x86)%`  | `C:\Program Files (x86)` |
      | `%TIME`                | Current time       |
      | `%USERPROFILE%`        | `C:\Users\{username}`    |
      |` %SYSTEMDRIVE%`        | `C:\`                    |
      | `%SYSTEMROOT%`         | `C:\Windows`             |

#### Bonus

7. Using the ENV variables `%ProgramFiles%` and `%ProgramFiles(x86)%`, list the contents of these directories and append them to the report.

----

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
