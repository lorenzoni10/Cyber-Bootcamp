## Activity File: Security Onion and NSM

In this activity, you will continue your role as an SOC Analyst for the California DMV. 

- You’ve implemented a new security control as part of your network security monitoring (NSM) program.

- Your NSM program will help your organization understand the limits of what it can detect, adversarial tactics, and how to quickly apply lessons learned to mitigate newly discovered security vulnerabilities.

- Your CISO has advocated for using Security Onion as your open source NSM system to detect and analyze all intrusion attempts. 

- Your CISO provided the following questions to help you test your knowledge of Security Onion and NSM before launching the new system. 

### Instructions

For the following section, you will need to log into Azure and launch an instance of Security Onion.

Log in with the following credentials:

- Username: `sysadmin`
- Password: `cybersecurity`

Complete the following:

1. Click the Sguil desktop icon and launch the application.

2. Log in using the same credentials.
    - Username: `sysadmin`
    - Password: `cybersecurity`

  - When prompted, select **both** networks to monitor. 
  
3. Pick one alert and answer the following questions:

    - What is the alert status?
    - What are the source and destination IP addresses?
    - What are the source and destination ports?
    - In the IP resolution section, perform a reverse DNS lookup of the attacker. What information is revealed?
    - What is the alert ID for the alert you chose?

4. Define the Snort rule that triggers the alert you chose:

    - Action
    - Protocol
    - Source IP
    - Source port
    - Direction
    - Destination IP
    - Destination port
    - Message

#### Bonus Questions

Answer the following questions as true or false:

1. NSM is vulnerability-centric, with its primary focus on the vulnerability and not the adversary.


2. The strength of NSM is its focus on the visibility of an attack, not its control.


3. NSM can see inside encrypted traffic.


4. Alerts in Security Onion's Sguil console are the equivalent of an Indicator of Attack, or IOA.


5. NSM allows organizations to track and uncover malware.


6. The Snort IDS engine drives the functionality of the Sguil analyst's console.


Answer the following questions:

1. Name two methods for physically connecting an IDS to a network.


2. Name the two stages of NSM and their processes.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
