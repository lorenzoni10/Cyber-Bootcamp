## Solution Guide: Uploading Data in Splunk 

In this activity, you were provided several different types of log files and tasked with uploading them into your Splunk repository for later analysis.

--- 

1. Log into Splunk


2. Use the Splunk data upload feature to load the log files.

    - Select the **Settings** tab on the top of the Splunk application.
    - Under this tab select **Add Data**.

    - Click through all the default options provided on the top of the screen.

    - On the **Select Source** page, click **Select File**, then select one of the three files to upload. For example, select `carbon_black.txt`.

    - Click **Next** to move to the **Set Source Type** page, and select **Next** again.

3. Give each file the same name as the log file.

    - A **Save Source Type** page should pop up.
    
    - Enter in the name, such as "carbon_black."
    
    - Leave the other fields as-is and click **Save**.

    - Select **Review** on the **Input Settings** page.
   
    - Select **Submit**.
   
    - If the file loads successfully, you will see a message saying "File has been uploaded successfully."

    - Select **Start Searching** to view the data.

4. Provide a brief summary about each log file: 

    - `carbon_black.txt` provides endpoint security logs that are designed to detect suspicious behavior.

    - `nessus.txt` provides logs for vulnerability scans on an organization's computer assets.

    - `win_security_events.txt` provides event logs for Windows operating systems.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
