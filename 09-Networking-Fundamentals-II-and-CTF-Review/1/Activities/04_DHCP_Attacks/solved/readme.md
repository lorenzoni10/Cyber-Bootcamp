## Solution Guide: DHCP Attacks

In the exercise, you analyzed a packet capture from Acme Corp to investigate the type of network attack preventing employees from accessing the internet.

Completing this activity required the following steps:
- Opening a packet capture of network traffic from Acme Corp.

- Creating filters for different types of DHCP activities.

- Summarizing findings to determine which type of attack has occurred and how it'is preventing employees from accessing the internet.
   
---


- Create a filter to determine the count for each different DHCP activity:

  **DHCP Discover**
    
  - Filter: `dhcp.option.dhcp == 1`
  - There are 135 DHCP Discover packets.
    
  **DHCP Offer**
    
  - Filter: `dhcp.option.dhcp == 2`
  - There are 15 DHCP Offer packets.
    
  **DHCP Request**
    
  - Filter: `dhcp.option.dhcp == 3`
  - There are 0 DHCP Request packets.


- Based on these results, summarize what type of attack may have occurred, and why you believe Acme Corp's employees are having network issues.

  - Having found 135 DHCP Discover packets for a short period of time, we can say that this is a **DHCP starvation attack**. 

  - Because there were many DHCP requests, the list of available IP addresses was used up. 

  - Due to this, staff trying to connect to the network are unable to get a new IP address. 

- Analyze the source MAC addresses of the DHCP activities and summarize what the attacker is doing.

  - For each DHCP request, the attacker is changing their MAC address.  They are likely using a spoofing tool to create a new MAC address for each request to successfully run the DHCP starvation attack.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
