## Activity File: Searching Fields with Splunk

- Your manager at OMP is concerned with suspicious user activity on the Windows servers.

- Several OMP users are being locked out and deleted. 

- You have been tasked with creating several complex SPL queries by selecting fields in your Splunk search.

### Instructions

1. Load and open the Windows logs in your Splunk search, specifically the logs named: `winevent_logs.csv`
  - Note: There are several windows logs. Make sure you are selecting the correct one: `winevent_logs.csv`

2. Select fields to design SPL queries that pull the following data. (**Hint:** Check the name field for activities.)

    - Logs for when a user was locked out.

    - Logs for when a user account was deleted.

    - Logs for when a user was locked out and on the dest_nt_domain of Domain_B.

    - Logs for when a user account was deleted and on the dest_nt_domain of Domain_B on Tuesday.
  
3. Run the searches and note how many events are returned. 

#### Bonus

- Create an SPL query to determine the type of user activity for the EventCode of 4738.
    

---
  
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
