## Solution Guide: Splunk Statistics 

In this activity, you were tasked with creating several statistical reports as well as creating a new field for a specific use case.

---
1. Using the same Fortinet log file from the last activity, design SPL queries to display the following statistical reports.

    - Top 20 destination IP addresses:
      - Select **dest_ip**, then **Top values**.
      - SPL query: 
          - `source="fortinet_IPS_logs.csv" | top limit=20 dest_ip`

    - Top 10 source IP addresses (with count and percent):
      - Select **src_ip**, then **Top values**.
      - Change the top limit from 20 to 10.
      - SPL query: 
          - `source="fortinet_IPS_logs.csv" | top limit=10 src_ip`

    - Top 10 source IP addresses / source port combination (with count and percent):
      - Using the previous SPL query, add the source port to the search.
      - SPL query: 
        - `source="fortinet_IPS_logs.csv" | top limit=10 src_ip, src_port`
 
2. Using `eval`, create a field called `DB_Type` to help identify a sensitive database (`12.130.60.5`) that contains customer data:
    - `source="fortinet_IPS_logs.csv"  | eval DB_type  = if(dest_ip == "12.130.60.5","Customer DB","Non-Customer DB")`

3. Display the results of this field in a statistical report:

    - `source="fortinet_IPS_logs.csv"   | eval DB_type  = if(dest_ip == "12.130.60.5","Customer DB","Non-Customer DB")| top limit=20 DB_type`


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
