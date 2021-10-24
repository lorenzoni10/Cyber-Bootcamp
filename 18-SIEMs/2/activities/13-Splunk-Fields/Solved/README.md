## Solution Guide: Splunk Fields

---
Open the Windows logs in your Splunk search.

  -  `source="winevent_logs.csv"`

Select fields to design SPL queries that pull the following data. 

- Run the searches and note how many events are returned. 

    - Logs for when a user was locked out: 

      - In the name field, select "A user account was locked out."

      - SPL query: `source="winevent_logs.csv" name="A user account was locked out"`

      - This will return 293 events.

  - Logs for when a user account was deleted:

    - In the name field, select "A user account was deleted."

    - SPL query: `source="winevent_logs.csv" name="A user account was deleted"`

    - This will return 283 events.

  - Logs for when a user was locked out and on the dest_nt_domain of Domain_B:

    - In the name field, select "A user account was locked out" and for the dest_nt_domain field select `Domain_B`.

    - SPL query: `source="winevent_logs.csv" name="A user account was locked out" dest_nt_domain=Domain_B`

    - This will return 66 events.

  - Logs for when a user account was deleted and on the dest_nt_domain of Domain_B on Tuesday:

    -  In the name field, select "A user account was locked out." For dest_nt_domain field, select `Domain_B`. For date_wday, select `tuesday`.

    - SPL query: `source="winevent_logs.csv" name="A user account was locked out" dest_nt_domain=Domain_B date_wday=tuesday`

    - This will return 66 events.

  
#### Bonus

Create a SPL Query to determine the type of user activity for the EventCode of 4738:
    
  - SPL query: `source="winevent_logs.csv" EventCode=4738`
  - After running this query, there is only one value that appears under the name field: "A user account was changed."

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.   
    
    
