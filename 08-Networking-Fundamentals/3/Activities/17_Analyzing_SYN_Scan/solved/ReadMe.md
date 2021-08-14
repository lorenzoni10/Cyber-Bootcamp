## Solution Guide: Analyzing a SYN Scan

This activity demonstrated how a SYN Scan can be used by a network professional to determine the state of a communication port without establishing a full three-way connection.  

Completing this activity required the following steps:

   - Loading the packet capture with Wireshark.
   
   - Analyzing the SYN Scan to determine what ports are open, filtered, and closed. 
	
---

In Wireshark, open the `synscan.pcapng` file.

Analyze the SYN Scan to determine what ports are open.

- An open port would show the following five steps:
   1. SYN request
   2. SYN/ACK response
   3. SYN/ACK response
   4. SYN/ACK response
   5. SYN/ACK response
	
- To analyze the open ports:

   - Navigate to `Statistics` > `Conversations`.
   - Select the `TCP` tab.
   - Sort descending by packets.

- The three open ports with five packets are: `53`, `80`, and `22`.

 
Analyze the SYN Scan to determine what ports are closed.


- A closed port would show the following two steps:
	
   1. SYN request
   2.  RST/ACK response
      
- To analyze the closed ports:

   - Navigate to `Statistics` > `Conversations`. 
   - Select the `TCP` tab.
   - Sort descending by packets. 

- The five closed ports with two packets are: `113`, `113`, `25`, `31337`, `70`.


Analyze the SYN Scan to determine what ports are filtered. 


- A filtered port would show the following step:
	
   1. SYN request
	
- To analyze the filtered ports:

   - Navigate to `Statistics` > `Conversations`. 
   - Select the `TCP` tab.
   - Sort descending by packets. 

- The filtered ports are all the other ports that are not open or closed. There are many of them.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.



