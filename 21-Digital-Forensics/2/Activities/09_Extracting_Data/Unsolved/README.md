## Activity File: Extracting Evidence for Offline Analysis
   

In this activity, you will continue your role as a digital forensic investigator.
 
- You are tasked with exporting the call history database and logs directory for offline examination. 

- This will allow other investigative team members to use alternative methods to analyze, parse, and create reports outside of Autopsy.
 
- The investigative team will use your file and directory exports to identify and confirm Tracy's phone number.


### Instructions

#### Single File Export
 
A senior investigative team member has asked you to export the `call_history.db` file for offline analysis.

  1. Locate the `call_history.db` file in the iPhone image file.
 
  2. Extract the file to the `Export` directory located at `/root/casedata/2012-07-15-National-Gallery/Export`.
 
Now you will view the file using SQLite DB Browser, the third-party application used by your team. It is professional courtesy to verify your exports prior to handing them off to other team members.
 
  3. Open a new terminal window and navigate to the `/root/casedata/2012-07-15-National-Gallery/Export` directory.
 
  4. Run the following command: `sqlitebrowser call_history.db`.
 
   The SQLite DB Browser will open.
 
  5. Click the **Browse Data** tab.
 
  6. Select **call** in the Table dropdown menu to reveal the call history.
 
  **Bonus**
 
  - What is the command to launch and simultaneously open the call table?
 
#### Full Directory Export  
 
You were also asked to export the entire `logs` directory for further offline analysis. The team will use this file to locate and confirm Tracy's phone number.
 
  1. Navigate to the `vol5/logs` directory in the **Directory Tree** pane.
  
  2. Export the entire directory to `/root/casedata/2012-07-15-National-Gallery/Export`.
 
Parse the file for Tracy's phone number to verify the correct file was exported.
 
  3. Open a new terminal window, navigate to the `/root/casedata/2012-07-15-National-Gallery/Export` directory, and `cd` into the newly created `logs` directory.
 
#### Data Export Analysis 

1. Open the `lockdownd.log.1` file in a text editor of your choice.
 
2. Ensure you `cd` into the log directory, and pipe `cat lockdownd.log.1` to `less`.
 
3. Parse the file and extract Tracy's phone number.
 
   - What is Tracy’s phone number?
 

----
 
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.

