## Solution Guide: SPL Search
In this activity, you had to write several SPL queries to analyze certain security situations.

---

Using SPL, design queries to display the following data from the `nessus.txt` logs.

Run your designed queries within Splunk and determine the count returned for each query.

  - Display results where OS contains "Windows".
    - `source="nessus.txt" os="*Windows*"`

    - Total: 408 events

  - Display results where OS contains "Linux".
    - `source="nessus.txt" os="*Linux*"`

    - Total: 344 events

  - Display results where `dest_ip` is `10.11.36.4`.
    - `source="nessus.txt"  dest_ip="10.11.36.4"`

    - Total: 15 events

  - Display results where `dest_ip` starts with `10.12.34`.
    - `source="nessus.txt"  dest_ip="10.12.34*"`

    - Total: 670 events 

### Bonus 

* Design an SPL search to display results where the signature contains an RDP man-in-the-middle weakness.

   - `source="nessus.txt" signature="Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness"`

   - Total: 152 events 

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  