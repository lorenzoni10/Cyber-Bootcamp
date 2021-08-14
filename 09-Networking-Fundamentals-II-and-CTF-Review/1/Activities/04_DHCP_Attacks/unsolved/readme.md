## Activity File: DHCP Attacks

In this activity, you will play the role of a security analyst at Acme Corp.

- Acme Corp employees are currently experiencing network access issues and are unable to connect to the internet.

- These employees are receiving error messages saying no local IP addresses are available, indicating a potential issue with DHCP.

- Acme believes an internal attack may have occurred and would like you to investigate by analyzing a packet capture to determine what type of attack may be causing the issue.

### Instructions
   
Open the provided packet capture with Wireshark.

1. Create a filter to determine the count for _each_ DHCP activity:
    - DHCP Discover
    - DHCP Offer
    - DHCP Request

2. Based on these results, summarize what type of attack may have occurred, and why you believe Acme Corp's employees are having network issues.

#### Bonus
 - Analyze the source MAC addresses of the DHCP activities and summarize what the attacker is doing.
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.