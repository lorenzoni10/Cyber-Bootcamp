## Activity File: Email Export
 
In this activity, you'll continue in the role of digital forensic investigator.

- Your task is to export the email database for offline examination.
 
- You and the investigative team will use this offline email file to find additional incriminating evidence in an upcoming activity.

### Instructions
 
1. Open your case file in Autopsy:
 
   - Start the Kali VM and open a terminal.

   - Navigate to: `/root/autopsy-files/autopsy-4.10.0/bin`

   - Run `./autopsy` to launch Autopsy.

   - Open the recent case:
      - Case name: `2012-07-15-National-Gallery`
      - Case number: `1EZ215-P`
 
2. A senior investigative team member has asked you to export the `INBOX.mbox` file for offline analysis:

    - Locate the `INBOX.mbox` file by using the keyword search in the top-right toolbar and selecting **Exact Match**.

    - Extract the file to the `Export` directory located at `/root/casedata/2012-07-15-National-Gallery/Export`.
 
3. Verify the export:
 
   - Open a new terminal window.
 
   - Navigate to the `Exports` directory and `cd` into the `43149-INBOX.mbox` directory.
 
   - Run `ls -l`.  Take note of the two folders present:
 
      - `Attachments`
      - `Messages`
 
   - `cd` into the `Messages` directory and take note of the EMLX files.
 
You have successfully exported Tracy's emails for offline analysis.
 
We will examine these emails in upcoming activities to establish Tracy's involvement in this case and uncover the identity of any co-conspirators.
 

----

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
