## Solution Guide: Splunk Reports 

In this activity, you were tasked with creating a scheduled report and sending an email notification.

---

To create the scheduled report:

- Enter  `source="fortinet_IPS_logs.csv"   | eval DB_type  = if(dest_ip == "12.130.60.5","Customer DB","Non-Customer DB")| top limit=20 DB_type` in the query and select **Search**.

- Click **Save As** > **Report**.

- Title the report "DB Server Attack Report."

- Select **Save**.

- On the next page, select the **Schedule** option.

- Check **Scheduled Report**.

- Schedule the report to run:
  - Every day at 12 p.m.
  - Time range of 24 hours.
  - Leave all the other options the same.

- Select **Add Action** > **Send Email**.
  - Send to management@ompcompany.biz.
  - Set the subject to "Database Attack Report."
  - Set the message to "Your daily database attack report is now available."
  - Un-check all the **Include** checkboxes.

- Click **Save**.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  