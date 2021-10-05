## Solution Guide: Ports

The goal of this exercise was to introduce you to ports and demonstrate that each protocol is assigned a specific port number.

This activity required the following steps:
   
   - Open the log file to view the various log records.
   
   - Determine the source and destination port for each log record.
   
   - Determine the protocol for the associated destination port.
   
   - Determine what kind of activity may be occurring based on the protocol.

---


When you open the log file, you'll see the source and destination port in each record. It will resemble the following example:
 
 `Src Port: 50152, Dst Port: 80`
 
**Log Record 1**
 
  - Source Port: `50152`
  - Destination Port: `80`
  - Destination Protocol: `HTTP`
  - Protocol Summary: Sally Stealer is likely accessing an unencrypted website.


**Log Record 2**		
  
  - Source Port: `53367`
  - Destination Port: `443`
  - Destination Protocol: `HTTPS`
  - Protocol Summary: Sally Stealer is likely accessing a website with encrypted traffic.

**Log Record 3**

  - Source Port: `64836`
  - Destination Port: `21`
  - Destination Protocol: `FTP`
  - Protocol Summary: Sally Stealer is likely using FTP to transfer files.
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


