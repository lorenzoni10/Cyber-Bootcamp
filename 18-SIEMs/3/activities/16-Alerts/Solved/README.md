## Solution Guide: Scheduling Alerts

In this activity, you were tasked with designing and scheduling an alert to notify via email that a brute force attack is occurring.

---

- Enter the SPL query: 
  - `source="windowsrawlogs.txt" EventCode=4625`
  
  - Select **Save As** > **Alert**.

- Title the alert "Brute Force Alert."
- Set the alert to run every hour.
- Set the trigger alert to the threshold chosen in the last activity.
    - For example, if the threshold is set to seven, set the alert to trigger if the count is greater than six.
- Leave all the other fields as they are.

- Select **Add Actions** > **Send email**.
    - Email: SOC_Team@ompcompany.biz
    - Email Subject: "Brute Force Alert"
    - Message: For example, "This is an alert of a potential brute force on the Windows machine. The bad logins attempt has reached 7 in an hour.  Please investigate."
  


#### Bonus
 
- Load the file and run the SPL query:
   -  `source="bonus_logs.txt" EventCode=4625`

- Note the spike in activity at approximately 5 a.m. on February 12th.
- The average normal activity for bad logins is approximately 108 bad logins per hour. Note that this is a rough estimate.
- A good estimate for a threshold is 175 bad logins per hour. This estimate based on the average bad logins vs. the spike.
- To create an alert, repeat the same steps as for the last alert.

  - Enter SPL query:
    - `source="bonus_logs.txt" EventCode=4625`.

    - Select **Save As** > **Alert**.
    
  - Title: "Brute Force Alert" 
  
  - Set the alert to run every hour.
  
  - Set the trigger alert to go off when the count of events is greater than 174. 
  
  - Select **Add Actions** > **Send email**.

    - Email: SOC_Team@ompcompany.biz 
    - Email Subject: "Brute Force Alert"
    - Message: For example, "This is an alert for a potential brute force on the Windows machine, the bad logins attempt has reached 175 in an hour. Please investigate."

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
