## Activity File: Threat Hunting - Cyber Threat Intelligence

In this activity, you will continue in your role as an SOC analyst for the California DMV. 

- The SOC has succeeded in detecting alerts since system launch. As a result, your CISO has advocated for additional funding.

- Now that you're more experienced using the NSM system, you’ve realized that you must detect threats early in the process, before they cause significant damage. 
 
- You’ve made the decision to move from traditional network-based IDS engines, such as Snort, to a more all-encompassing ESM that includes endpoint telemetry. This involves the deployment of endpoint collection agents in the form of a host-based IDS system using OSSEC.

- You've decided to include threat hunting as part of your defense strategy. You assembled a team of highly motivated security professionals to help you.

- In this activity, you will strengthen your knowledge of concepts related to intelligence gathering and incidence response as part of the ESM process. You can use any tool you've learned to hunt for any malicious threat.

### Instructions

Choose a threat and use the following threat intelligence card template to document your findings: 

- [Threat Intelligence Card](https://docs.google.com/document/d/1nG1F5sD1GC3EqZo6a4VMOmBltS7qYAkgf4AfFsFrXu0/edit#).

#### Sample Threat Intelligence Report 

If necessary, refer to the following sample report for guidance:

1.  What indicator of attack did you use to begin your investigation?

    - Red Alert on analyst console ("GET /crusher.exe HTTP 1.1" with server response "HTTP /1.1 200 OK" for unauthorized file download)
    
    - Alert profile:
      - Source IP: 10.0.135.19
      - Destination IP: 192.168.0.45
      - Source port: 3345
      - Destination port: 25
      - Infection type (Trojan, Virus, Worm, etc.): Trojan/RAT

2. What was the adversarial motivation (purpose of attack)?

    - Theft of Personally Identifiable Information (User names/addresses/account numbers) for sale on the Dark Web.

3. What were the adversary's Tactics, techniques, and procedures?

   | TTP | Examples of Cyber Kill Chain penetration |
   | --- | --- |
   | **Reconnaissance** | The threat actor utilized online resources such as Facebook, DNS registration websites, and the "About" page of the company website.|
   | **Weaponization** | The creation of a Remote Access Trojan or RAT Downloader. |
   | **Delivery** | A breached corporate email account. |
   | **Exploitation** | Crusher.exe is an executable hidden inside of a .pdf document that establishes persistence by modifying Windows registry key **C:\ Windows\System32\config** under the names **SAM**, **SECURITY**, **SOFTWARE** and **SYSTEM**. |
   | **Installation** | A user who clicks on the email attachment. |
   | **Command & Control (C2)** | A command channel tunnels through Internet Relay Chat (IRC) establishing a connection to the attacker's server.|
   | **Actions on Objectives** | Attacker exfiltrates private user account information.|

4. What are your recommended mitigation strategies?

   - Implement administrative security controls (Security Awareness Program) regarding malicous emails.
   - The deployment of Data Loss Prevention software DLP on host workstations.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
