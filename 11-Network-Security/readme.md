
## Unit 11 README: Network Security

### Unit Description

This week is an introduction to network security from both a theoretical and practical standpoint. We'll explore the benefits of using defense in depth methodologies and how firewalls serve as the network's primary defense mechanism at both the perimeter and interior of the network.

A critical skill of the network defender is to not only be able to stop an attack but also to learn from them. We will explore in great detail how to establish situational awareness of our networks using detailed data analytics to learn about the tactics, techniques, and procedures (TTP) that adversaries use to successfully infiltrate networks.

- Day 1 introduces firewalls. We'll examine the relationship between ports and services, including the role open ports play as the principal attack surface of networked machines. Then, we'll cover how firewalls are used to control access to a machine's open ports.

- Day 2 covers intrusion detection systems (IDS) and network security monitoring (NSM). We will analyze indicators of attack and compromise (IOAs and IOCs), perform network forensics, and acquire adversarial intelligence and situational awareness of our networks.

- Day 3 focuses on threat hunting using the Enterprise security management (ESM) framework of network security tools. We'll examine ESM concepts and the role of host-based endpoint telemetry, simulate investigations, and perform alert triage using Kibana.


### Unit Objectives 

<details>
    <summary>Click here to view the daily unit objectives.</summary>

  <br>

- **Day 1:** Introduction to Firewalls and Network Security
  - Explain how open ports contribute to a computer's attack surface.
    
  - Use firewalls to protect a computer's open ports.
    
  - Develop and implement firewall policies using UFW and firewalld.

    
- **Day 2:** Introduction to Intrusion Detection, Snort, and Network Security Monitoring
  - Interpret and define Snort rules and alerts.
    
  - Explain how intrusion detection systems work and how they differ from firewalls.
    
  - Use Security Onion and its suite of network security monitoring tools to trace the path of network attacks.
    
  - Collect and analyze indicators of attack and indicators of compromise using NSM tools.
    
  - Apply knowledge of NSM, Snort rules, and Security Onion to establish situational awareness within a network.


- **Day 3:** Enterprise Security Management (ESM)

    - Analyze indicators of attack for persistent threats.

    - Use enterprise security management to expand an investigation.

    - Use OSSEC endpoint reporting agents as part of a host-based IDS alert system.

    - Investigate threats using various analysis tools.

    - Escalate alerts to senior incident handlers.


</details>


### Lab Environment

In this unit, you will be using the NetSec lab environment located in Windows Azure Lab Services. RDP into the Windows RDP Host machine using the following credentials:

  - Username: `azadmin`
  - Password: `p4ssw0rd*`

Open Hyper-V Manager to access the below machines:

  - Security Onion Machine

    - Username: `sysadmin`
    - Password: `cybersecurity`

  - UFW Machine

    - Username: `sysadmin`
    - Password: `cybersecurity`

  - firewalld Machine
- Username: `sysadmin`
    - Password: `cybersecurity`


### What to Be Aware Of

- Days 2 and 3 will begin with a quick setup process so our machines can generate alert data for the lab activities.

- In Day 3, you will sign up for Azure personal accounts.

    - In the next unit - Unit 12 - we will cover cloud security and virtualization, followed by a project week. In these two units, you will use your own individual Azure account. You will not be using your cyberxsecurity accounts during these weeks. 

    - You must create and set up a new Azure account to use for the next two weeks. You will sign up for your personal Azure accounts at the end of Day 3. Please DO NOT sign up for accounts beforehand; Azure provides a $200 credit that is valid for only 30 days. We ask that you wait as close to Unit 12 as possible in order to ensure that you have enough time to complete the activities in Unit 12 and Unit 13.

   - Please have your account ready before the beginning of Unit 12 to avoid having to troubleshoot in class. 
        - This [Setup Guide](https://docs.google.com/document/d/1gs_09b7eotl7hzTL82xlqPt-OwOd0aWA78qcQxtMr6Y/edit) will guide you through the Azure account setup. Please be ready to get set up on 11.3

### Security+ Domains

This unit covers portions of the following domains on the Security+ exam:

- 1.0 Attacks, Threats, and Vulnerabilities 
- 2.0 Architecture and Design 
- 3.0 Implementation
- 5.0 Governance, Risk, and Compliance

For more information about these Security+ domains, refer to the following resource: [Security+ Exam Objectives](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-security-sy0-601-exam-objectives-(2-0).pdf?sfvrsn=8c5889ff_2)


### Additional Reading and Resources

<details> 
<summary> Click here to view additional reading materials and resources. </summary>
</br>

These resources are provided as optional, recommended resources to supplement the concepts covered in this unit.

- **Day 1 Resources**

  - [CSO: What is network security? Definition, methods, jobs & salaries](https://www.csoonline.com/article/3285651/what-is-network-security-definition-methods-jobs-and-salaries.html)

  - [Cisco: What is Network Security?](https://www.cisco.com/c/en/us/products/security/what-is-network-security.html)

  - [Cyberseek: Career Heat Map](https://www.cyberseek.org/heatmap.html)


- **Day 2 Resources**

  - [CSO: What is an intrusion detection system?](https://www.csoonline.com/article/3255632/what-is-an-intrusion-detection-system-how-an-ids-spots-threats.html)

  - [Security Onion: Documentation](https://docs.securityonion.net/en/16.04/)

  - [Security Onion: Cheat Sheet](https://github.com/Security-Onion-Solutions/security-onion/wiki/Cheat-Sheet)

- **Day 3 Resources**

  - [Kaspersky: What Is an Advanced Persistent Threat (APT)?](https://www.kaspersky.com/resource-center/definitions/advanced-persistent-threats)

  - [MITRE: ATT&CK Matrix for Enterprise](https://attack.mitre.org)


</details>

---

### Unit 11: Homework

This unit's homework assignment can be viewed here: 

- [Unit Homework File](Homework/README.md)

### Looking Forward 

Next week we will cover cloud security and virtualization, followed by a project week. In these two units, you will use your own individual Azure account. 

- :warning: **Heads Up**: You will **not** be using your cyberxsecurity accounts during these weeks. You must create and set up a new Azure account to use for the next two weeks. Please review the instructions above in the "What to Be Aware of Section" 


---


© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
