## Solution Guide: Analyzing ARP 

This exercise introduced the Layer 2 protocol ARP, how ARP requests and responses work, and the security risks they can  introduce. Additionally, it demonstrated how MAC addresses are used with ARP.

The activity required the following steps:
   - Opening the packet capture to view ARP requests and responses.

   - Analyzing the ARP responses to determine the physical MAC addresses for each IP address.

   - Further analyzing the packet capture to identify an ARP poisoning attack.

---


Open the packet capture file in Wireshark.

- To filter for ARP replies, use the `opcode` filter:

    `arp.opcode == 2`
    
   This field specifies the nature of the ARP message, in which `1` is a request and `2` is a reply.  To find the replies and determine the physical addresses, use the above filter.
  	  
- Document the physical addresses found for each of the following IP addresses:	 

   - In the field that starts with "Ethernet II", the MAC address is listed as: `00:50:56:c0:00:08`.

      - 192.168.47.2
      

   - In the field that starts with "Ethernet II", the MAC address is listed as: `00:50:56:fd:2f:16`.

      - 192.168.47.200

   - In the field that starts with "Ethernet II", the MAC address is listed as: `00:0c:29:0f:71:a3`.

      - 192.168.47.254 

   - In the field that starts with "Ethernet II", the MAC address is listed as: `00:50:56:f9:f5:54`.

- Further analyze the packet capture to determine if these IPs present any potential security vulnerabilities. 

    - Further down in the ARP responses are ARP responses for IP addresses that have already been provided a MAC address. These requests include new MAC addresses.
 
   - These responses include this message:
 
      `Duplicate IP address detected for 192.168.47.1 (00:0c:29:1d:b3:b1) - also in use by 00:50:56:c0:00:08 (frame 22)`
 
   - This is a potential indicator of an **ARP poisoning attack**—when attackers attempt to submit a malicious server to the ARP cache in order to steal traffic intended for the correct server.

**Bonus** 

- Name a few ways to protect against this vulnerability.

  - Creating a static ARP entry in your server can help reduce the risk of ARP poisoning.

  - Third-party tools can identify and alert for potential ARP poisoning attacks.

- Determine the primary vendor for the MAC addresses.  
    
   - Many web tools can assist with looking up the vendor associated with a MAC address. 

   - The web tool at aruljohn.com/mac.pl identifies all the MAC addresses vendors as VMWare.
   
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.