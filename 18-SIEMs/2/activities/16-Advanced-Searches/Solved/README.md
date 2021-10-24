## Solution Guide: Advanced Searches with Piping 

In this activity, you practiced using advanced Splunk searches and piping to assist with analyzing and presenting security events.

---

1. Design SPL queries to look at the following activity types:

    - An account was successfully logged on:
      - `source="winevent_logs_2.csv"  name="An account was successfully logged on"`

    - A user account was changed:
      - `source="winevent_logs_2.csv"  name="A user account was changed"`

    - System security access was granted to an account:
      - `source="winevent_logs_2.csv"  name="System security access was granted to an account"`

    - A user account was deleted:
      - `source="winevent_logs_2.csv"  name="A user account was deleted"`

    - A user account was locked out:
      - `source="winevent_logs_2.csv"  name="A user account was locked out"`


2. Out of these results, is there an an Account_Name that has a majority of the activity records? Which activity type is it?
  
   - `user_d` is the Account_Name that appears the most for the activity "A user account was locked out."

3. Design an SPL query to present the results to your manager with the following information:
    -  The activity type found in Step 2.
    -  The primary Account_Name.
    -  Simplify the query results to only show the top 50 rows sorted by ComputerName. 
  
   `source="winevent_logs_2.csv" name="A user account was locked out" Account_Name="user_d" | head 50 | sort ComputerName` 

4. Provide a written summary to your manager about what your finding may mean.

   - `user_d` is experiencing a high level of "User account was locked out" errors, which indicates an attacker is potentially attempting to brute force into this account.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  

