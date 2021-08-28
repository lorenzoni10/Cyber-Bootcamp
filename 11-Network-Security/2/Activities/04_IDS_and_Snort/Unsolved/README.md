## Activity File: Intrusion Detection Systems and Snort

In this activity, you will play the role of an SOC analyst for the California Department of Motor Vehicles (DMV). 

- In preparation for the California Consumer Privacy Act (CCPA), which will start to be enforced in 2020, your CISO has advised you to implement new security controls to further protect the driving records of all state citizens.

- This new law includes serious penalties for failing to provide adequate protection of private citizen data. As a result, you’ve decided to strengthen your layered defenses by adding both network-based (NIDS) and host-based intrusion detection systems (HIDS).

- You decided to deploy Snort as your newly added security control. You’ve also decided to deploy Snort at three layers of the defense in depth (DiD) model: Perimeter (NIPS), Network (NIDS), and Host (HIDS). 

- In preparation for the launch, your CISO prepared a review document for you and your staff to determine who needs additional training.

### Instructions

Read and answer each question.

1. What are the two main differences between a firewall and an IDS system?


2. What's the best physical placement for an IDS on a network: inline or mirrored port?


3. An IDS placed at the Perimeter layer of the DiD model is referred to as what?


4. Define each part of the following Snort alert:

    - `alert ip any any -> any any {msg: "IP Packet Detected";}`

        - `alert`

    
        - `ip`


        - `any any` 

    
        - `->`

    
        - `any any`

    
        - `{msg: "IP Detected";}`

 

5. An intrusion system that can act on an alert by blocking traffic is referred to as what?

    
6. Name the two types of detection techniques used by intrusion detection systems.

 
7. What type of IDS establishes its rules using a baseline?

 
8. True or False: Signature-based IDS systems are not effective against zero-day attacks.


9. When used together, which should be placed farthest from the data: a firewall, an IDS, or an IPS?

#### Bonus Questions
   
10. What part of this Snort alert is the "rule header"?

    - `alert ip any any -> any any {msg: "IP Packet Detected";}`

   
11. Name and define the three Snort configuration modes.


12. What is the difference between an IDS and an IPS?


13. True or False: An indicator of attack (IOA) occurs at some previous point in time, and an indicator of compromise (IOC) occurs in real time.


14. True or False: An IOA is "proactive" and an IOC is "reactive."


15. True or False: An IPS is physically connected "inline" with the flow of traffic, processes entire subnets of data, and requires more robust hardware.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
