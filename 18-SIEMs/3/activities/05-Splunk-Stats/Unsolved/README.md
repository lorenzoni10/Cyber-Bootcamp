## Activity File: Splunk Statistics

You continue to be the SOC manager at Omni Military Products.

- Your manager is concerned about the denial of service attack you discovered.

- You are tasked with creating several statistical reports to illustrate details about the DOS attack.

- Additionally, you are tasked with creating a field to identify attacks against a sensitive database server's destination IP `12.130.60.5`.

### Instructions

1. Using the same Fortinet log file from the last activity, design SPL queries to display the following statistical reports.

    - Top 20 destination IP addresses (with count and percent)
    - Top 10 source IP addresses (with count and percent)
    - Top 10 source IP addresses / source port combination (with count and percent)
    
2. Using `eval`, create a field called `DB_Type` to help identify a sensitive database (`12.130.60.5`) that contains customer data.
   - If the destination IP is `12.130.60.5`, set the `DB_Type` field to `Customer DB`.
  -  If the destination IP is not `12.130.60.5`, set the `DB_Type` field to `Non-Customer DB`.

3. Display the results of this field in a statistical report.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
