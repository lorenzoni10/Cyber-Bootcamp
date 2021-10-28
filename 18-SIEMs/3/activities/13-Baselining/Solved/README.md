
## Solution Guide: Baselining 

In this activity, you had to determine thresholds by baselining activity from a Windows server's activity.

---

1. Upload the provided Windows log file:
    - Select **Settings** > **Add Data**, and add the `windowsrawlogs.txt`.

2. Design a search to look at failed logins:
    - `source="windowsrawlogs.txt" EventCode=4625`

3. Determine when the attack happened:

    - A spike occurred at approximately 7 a.m. on February 11, 2020.  This is indicated by a much higher count of activity compared to the other hours.

4. Determine the approximate average of normal bad logins per hour:
  
    - Based on the `bad_logins` per hour, the number is approximately 2 per hour.

5. Determine a threshold of logins that will alert if a brute force is occurring.
  
    - There is no perfect answer to this: thresholds may be adjusted as the normal count of bad logins and count of attacks changes. 
    
        However, based on the normal average of bad logins vs. attacks, setting a threshold to seven bad logins per hour would likely identify attacks and minimize false positives.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
