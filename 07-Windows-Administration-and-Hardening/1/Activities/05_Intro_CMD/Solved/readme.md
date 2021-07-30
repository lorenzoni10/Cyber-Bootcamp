## Solution Guide: Intro to Task Manager and CMD

This activity allowed you to familiarize yourself with ending processes and executing basic command-line operations.


#### Solutions

1. Use Task Manager to end the following processes (tasks) if they are running:

   - Press **Ctrl**+**Alt**+**Del** or navigate to Task Manager through the Start menu. 

   - Once Task Manager is open, navigate to the Process tab and click the **Name** column to sort by process name.

   - If running, select each of the following processes and click **End Task**.

      - Apple Push
      - iCloud Services
      - iPod Service
      - iTunesHelper
      - Skype
      - Apple Push
      - TeamViewer (if it's still running)

2. Disable startup processes. Within the Startup tab, select each startup process and disable it, except for the following:

   - Microsoft OneDrive
   - Windows Security notification icon

3. Using the Windows command line, create a `reports` folder on the user's desktop where you'll store your findings.

  - Run `cd C:\Users\%USERNAME%\Desktop` to navigate into the directory where we will create our report. We'll create the report in the next step. 

4.  Print a line that reads `Baselining Report` and output it to a new `report.txt` file. This will create a title within your report.

  - Run `echo Baselining Report > report.txt` to create a report titled `report.txt`.

5. Print another line titled `Created by [your name here]` and append it to the file.

  - Run `echo Created by [your name here] >> report.txt` to add the subtitle.

Verify your commands worked by entering `type report.txt`.

6. Using ENV variables append the machine's operating system, date, and username to our report:

    - Run `echo %OS% system report created on %DATE% with logged in user, %USERNAME%. >> report.txt`

    - Run `type report.txt`

    - Your output should look like:
    
      ```console
      Baselining Report
      Created by [your name here]
      Windows_NT system report created on Thu 11/14/2019 with logged in user, azadmin.
      ```

**Bonus**

7. Using the ENV variables `%ProgramFiles%` and `%ProgramFiles(x86)%`, list the contents of these directories and append them to the report:

  - Run `dir "%ProgramFiles%" >> report.txt`

  - Run `dir "%ProgramFiles(x86)%" >> report.txt`

----

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
