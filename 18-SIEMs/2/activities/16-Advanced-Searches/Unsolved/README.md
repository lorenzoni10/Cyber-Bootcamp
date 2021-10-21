## Activity File: Advanced Searches with Piping

- Your OMP manager believes there is one specific user that is being targeted by an adversary.

- You have been tasked with running several advanced searches to determine which user is being targeted.


### Instructions

Load and open the **NEW** Windows logs in your Splunk search, specifically the logs named: `winevent_logs_2.csv`
  - Note: There are several windows logs, make sure you are selecting the correct one for this activity: `winevent_logs_2.csv`

1. Design SPL queries to look at the following activity types:

    - An account was successfully logged on.
    - A user account was changed.
    - System security access was granted to an account.
    - A user account was deleted.
    - A user account was locked out.

2. Out of these results, is there an an Account_Name that has a majority of the activity records? Which activity type is it?
	
    - **Hint:** Account_Name is different from the User field. In this case, the User field can be ignored.

3. Design an SPL query to present the results to your manager with the following information:

    -  The activity type found in the Step 2.
    -  The primary Account_Name.
    -  Simplify the query results to only show the top 50 rows sorted by ComputerName.
  
4. Provide a written summary to your manager about what your findings mean.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
