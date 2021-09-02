## Solution Guide: Intrusion Detection Systems and Snort

The goal of this activity was to reinforce concepts related to Snort rules and intrusion detection systems. An understanding of these concepts is critical to gaining insight into an attacker’s TTPs.

___

1. What are the two main differences between a firewall and an IDS system?

    - An IDS differs from a firewall in that it **detects** and **alerts** when triggered by a rule.

2. What's the best physical placement for an IDS on a network, inline or mirrored port?

    - Mirrored port

3. An IDS placed at the Perimeter layer of the DiD model is referred to as what?

    - Perimeter IDS

4. Define each part of the following Snort alert:

   - `alert ip any any -> any any {msg: "IP Packet Detected";}`

        - `alert`: The action that Snort will take when triggered.

        - `ip`: Applies rule to all IP packets.

        - `any any`: From any source IP address and from any source port.

        - `-->`: All traffic inbound from outside the network to inside the network.

        - `any any`: To any destination IP address and source port.

        - `{msg: "IP Detected;}`: The message printed with the alert when the rule is matched.

5. An intrusion system that can act on an alert by blocking traffic is referred to as what?

      - Intrusion prevention system or IPS

6. Name the two types of detection techniques used by intrusion detection systems.

      - Anomaly and signature

7. What type of IDS establishes its rules using a baseline?

    - Anomaly or behavioral

8. True or False: Signature-based IDS systems are not effective against zero-day attacks.

     - True

9. When used together, which should be placed farthest from the data: a firewall, an IDS, or an IPS?

     - A firewall

#### Bonus Questions

10. What part of this Snort alert is the "rule header"?

      - `alert ip any any -> any any`

11. Name and define the three different Snort configuration modes.

     - Sniffer Mode: Reads network packets and displays them to screen.
    
     - Packet Logger Mode: Performs packet captures by logging all traffic to disk.
    
     - NIDS Mode: Monitors network traffic, analyzes it, and performs specific actions based on administratively defined rules.

12. What is the difference between an IDS and an IPS?

    - An IPS can act on traffic by blocking it and preventing it from being delivered to a host based on the contents of the packet. An IDS cannot.

13. True or False: An indicator of attack (IOA) occurs at some previous point in time, and an indicator of compromise (IOC) occurs in real time.

    - False

14. True or False: An IOA is "proactive" and an IOC is "reactive."

     - True

15.  True or False: An IPS is physically connected "inline" with the flow of traffic, processes entire subnets of data, and requires more robust hardware.

     - True

--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
