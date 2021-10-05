## 11.3 Student Guide: Enterprise Security Management (ESM)

### Overview

In today's class, students will advance their network security knowledge by learning enterprise security management (ESM) and how host-based OSSEC IDS technology plays a critical role in endpoint telemetry. Students will expand their investigations of threats using Security Onion's Elastic Stack and the web-based data analytics visualization tool, Kibana using a process known as "Cyber Threat Hunting".

### Class Objectives

By the end of today's class, you will be able to:

- Analyze indicators of attack for persistent threats.

- Use enterprise security management to expand an investigation.

- Use OSSEC endpoint reporting agents as part of a host-based IDS alert system.

- Investigate threats using various analysis tools.

- Escalate alerts to senior incident handlers.


### Slideshow

The lesson slides are available on Google Drive here: [11.3 Slides](https://docs.google.com/presentation/d/131Dk-2IEz4WXyFY0ZBzq5H2dhg2zvUesqZcXX_Wbf30/edit)

___

### 01. Security Onion Set Up

- [Activity File: Security Onion Setup](Activities/01_Security_Onion_Setup/README.md)

###  02. Overview and Alert - C2 Beacon Setup (0:20)

#### Network Security Recap

- On Day 1, we covered how firewalls protect a network. On Day 2, we expanded our layers of network security to cover IDS and IPS systems.

- Today, we will turn our focus to learning how an adversary conducts network security attacks. Then, through a process known as cyber threat hunting, we will use advanced network security tools, such as Security Onion and ELK, to gain a deeper understanding and situational awareness of a network's security posture.

#### C2 Alert Beacon Set Up

In the first activity, we'll explore how **command and control (C2) servers** are used to create a specific type of alert against attacks that use persistence as part of its attack campaign.

- NSM plays a critical role in implementing a defense in depth approach, serving as an additional layer of protection when an adversary bypasses defenses. 

- Attacks against these servers make infected hosts call back to C2 servers. These callbacks, referred to as "keep alives", serve as beacons that keep the back channel open, therefore enabling access in and out of the network at all times. 

- These keep alive beacons activate a specific alert. In the screenshot below, we see an alert identified as a C2 beacon acknowledgement. Note it includes the text `CnC Beacon Acknowledgement` in the Event Message. 

  ![Sguil Alert](Images/Sguill_Alert.png)

- There is a reference URL specified within the Snort rule option.

   - Sometimes, writers of Snort rules will put links in their rule options to help network defenders establish TTPs.

   - With this information, network defenders can form mitigation strategies to help improve their security posture.

![Snort Rule](Images/Snort_Rule.png)


### 03. C2 Beacon Activity

- [Activity File: C2 Beacon](Activities/04_C2_Beacon/Unsolved/README.md)

### 04. Review C2 Beacon Activity

- [Solution Guide: C2 Beacon](Activities/04_C2_Beacon/Solved/README.md)

### 05. Enterprise Security Monitoring 

Now that we've learned about the benefits of using firewalls and NSM, we must move from traditional network-based IDS engines, such as Snort, to the more all-encompassing **enterprise security monitoring** (**ESM**), which includes endpoint telemetry.

#### OSSEC

Firewalls and NSM cannot see inside of encrypted traffic. This is major limitation because:

- In most cases, malware will be transmitted from attacker to victim in an encrypted state, in order to hide its presence and intent. This also serves as a method of obfuscation to bypass IDS detection engines.

- Since malware cannot activate in an encrypted state, it must be decrypted. This can only happen after it is installed on the victim’s machine. This is where ESM and, more specifically, endpoint telemetry become relevant.

ESM uses OSSEC to provide visibility at the host level, where malware infection takes place after it's decrypted.

- OSSEC is the industry's most widely used host-based IDS (HIDS). It has many configuration options and can be tailored to the needs of any organization. 

- **Endpoint telemetry** as host-based monitoring of system data. 
   - OSSEC agents are deployed to hosts and collect syslog data. This data generates alerts that are sent to the centralized server, Security Onion. 

   - Security administrators can then use Security Onion to form a detailed understanding of the situation and reconstruct a crime.

#### Elastic Stack

OSSEC monitors all of the syslog data that it sees. However, not every syslog entry will generate an alert. Security admins will need to switch to other tools to fully analyze packet captures.

These other tools are known as the **Elastic (ELK) Stack**, the engine that operates within Security Onion. It consists of three important components:

1. **Elasticsearch** is considered the heart of the Elastic Stack. It is a distributed, restful search and analytics engine built into Security Onion that is capable of addressing thousands of data points seen within network traffic. It helps security administrators locate the expected and uncover the unexpected.

2. **Logstash** is an open-source, server-side data processing pipeline built into Security Onion. It ingests data from many sources at the same time by transforming it and sending it to designated log files, known as stashes.

3. **Kibana** is a browser-based visualization interface. It uses thousands of data points from the Elastic Stack as its core engine.

![OSSEC Log Management](Images/OSSEC.png)

These tools work together with OSSEC to make a comprehensive alert data process:

1. OSSEC agents generate an alert.

2. OSSEC sends alert data gathered from syslog to Security Onion's OSSEC server.

3. The OSSEC-generated syslog alert is written to Logstash for storage.

4. Log data is ingested into the Elasticsearch analytics engine, which parses hundreds of thousands of data points to prepare for data presentation.

5. Users interact with the data through the Kibana web interface.

#### Investigation, Analysis, and Escalation Demo

In this demo we will discuss using several tools in the ELK stack. We will focus on how these tools work, and not a specific attack. 

- We will also focus on the process of escalation within a Security Operations Center:

   - A junior analyst working in a Security Operations Center will belong to a multi-tier group of analysts. Junior analysts typically perform the initial triage of alerts and then escalate these events to senior incident responders.

- This process and the tools involved will be our focus.

We'll begin our investigation with a new tool called Squert:

- Click on the Squert desktop icon and enter the same credentials you used for you Sguil login.

- After logging in, we may need to change the date range to ensure we see all the alert data in our system. Click on the date range as illustrated below.

   ![Squert Date-Range 1](Images/Squert%20date%20range.png)


- The default view shows alerts from today. In order to show older alerts, click **INTERVAL**, then click the **two right arrows** to set your custom date. 

   ![Squert Date-Range 2](Images/Squert-date-set-1.png)

In this example we'll change the year to 2014 in the **START** field. This date range should cover all alerts used in the PCAPs.

-  Click on the **circular arrows** to reload the web page and refresh the alert data for the newly selected date range.

   ![Squert Date-Range 2](Images/Squert%20date%20set%202.png)

- Next, click on the word **QUEUE** to arrange the priorities from the highest count to the lowest. It may require two clicks.

   ![Squert Queue Alignment](Images/Squert%20que%20alignment.png)

- Clicking on a red number box will drop down that line and reveal several important items.

   - We can see URL links to two websites that provide additional insights into the attack.

   - As security administrators, we can use this research later in our incident investigations. It's encouraged to accumulate information from several different resources.

   ![Squert url Links](Images/Squert%20url%20Links.png)

- The screenshots below show the articles found at the links.

   - The articles, written by two different security researchers, provide incident responders with different insights into the same attack.

   ![Google Lookup 1](Images/Google%20Lookup%201.png)

   ![Google Lookup 2](Images/Google%20Lookup%202.png)

- Click on the **Views** tab at the top.

   - The Views tab displays traffic as it flows between a source and destination IP.
   
   - Scroll down to see more. 
   
   - Thicker bands indicate higher volumes of traffic.

   - This visualization indicates to security administrators potential problem areas that may require further investigation.


   ![Squert Views Thick Lines](Images/Squert%20views%20think%20line%20examples.png)

- Hover the mouse over a band and a window will pop up displaying the flow of traffic between source and destination IP using directional arrows.

   - The number of transmissions that have occurred is also displayed.

   ![Squert Views IP Pair](Images/Squert%20Views%20PopUP.png)

- Next we'll use Elastic Stack's data analytics engine through Kibana's web-based visualization tool. 

- Minimize the Squert window and open Sguil.

Launch Kibana by doing the following:

   - Right-click on any IP address.

   - A dropdown menu will appear. Select **Kibana IP Lookup**, and then select either the destination (**DstIP**) or source IP (**SrcIP**).

   ![Kibana Sguil Pivot](Images/Kibana_Pivot.png)

- After Kibana launches, you may be prompted to log in. If so, log in with the same credentials used for the Sguil client.

  - Once the web browser launches, it's best practice to verify that Kibana is using the correct filter, as seen in the screenshot below.

   - The IP address in the Kibana filter should match the one that we right-clicked to pivot from the Sguil client. In this case, it matches the IP that we used for this pivot, which is good.


   ![Kibana Dashboard Indicator](Images/Dashboard%20Indicator%20Filter.png)

- We have now started using the powerful Elastic Stack data analytics engine.

   - Elastic Stack is the heart of Security Onion's enterprise security monitoring capabilities. Kibana is the interface that provides insight into endpoint telemetry by interpreting the OSSEC agent syslog data.

In this next example, we'll begin our investigation by scrolling down to the **HTTP - Destination Ports** section.

- At this point in an investigation, we are looking for non-standard HTTP ports.

   - For example, if we saw port `4444` indicated here, that would be a clear indicator that a Metasploit Meterpreter session was in progress.


    ![Kibana HTTP Destination Ports](Images/HTTP%20Destination%20Ports.png)

Scroll down to the MIME word cloud.

- **MIME** (Multipurpose Internet Mail Extension) types (not a file extension), are used by browsers to determine how URLs are processed.

   - Therefore, it is important that web servers use the correct type of MIME.

   - Incorrectly configured MIME types are misinterpreted by browsers and can cause sites to malfunction and mishandle downloaded files.

   - Attackers use this to their advantage.

- In the graphic below, the Elastic Stack data analytics engine is displayed through Kibana's **MIME - Type (Tag Cloud)** visualization window.

   - The more a MIME type is discovered, the larger it appears in the word cloud.  

   ![Kibana MIME Example](Images/MIME%20example.png)

- If we scroll down a little further, we see **HTTP - Sites**, which lists the number of times particular websites have been visited. This is a good place to look for suspicious websites.

   - The **HTTP - Sites Hosting EXEs** section lists websites that were used to either download or search for an EXE. Again, anything that looks malicious will require further investigation.

   ![Kibana HTTP Sites Hosting EXEs](Images/HTTP%20Sites%20Hosting%20EXE.png)

- To investigate a malicious website, we apply a filter by hovering our mouse over the count and clicking the **+** sign. This will filter out all other websites.

- In the graphic below, the arrow pointing to the left will drop down the contents of the selected log, revealing its contents.

   - The arrow pointing to the right is the hyperlink to the PCAP file.

   - Clicking on this link will launch the PCAP in another window and display the TCP conversation using either TCP or HTTP flow.

   ![Kibana - bro_log Pivot](Images/bro_log%20Pivot.png)

- Now, using the image above as an example, click on the **triangle arrow pointing to the right**.
   - This will drop down the log file and reveal its contents, as shown in the screenshot below.  

   ![Kibana - bro_log table example](Images/Screen%20Shot%202020-02-11%20at%2010.26.30%20PM.png)

   - In our screenshot example, we can see the message `A Network Trojan was detected`, as indicated in the `classification` field.

   - We can also see that the `event_type` is indicated as `snort`.
      - An event type is the source of the alert, i.e., the application that generated the alert.

      - This entry is the result of an endpoint Snort IDS engine alert.

- Scroll up and click the link under **_id**. We can see the PCAP pivot. We can learn three facts from this view: 
   - The configuration is set to IDS and not operating in IPS mode. A download _could_ have occurred.  
   - We can see the HTTP response **SRC: Connection: Close**, meaning it closed when the victim got to this page. 
   - We can also see an **error 302**, meaning the website had moved.

   From this we can assume the following likely happened:
     - The victim clicked on a malicious link.
     - The link opened a window which downloaded or attempted to download the trojan.
     - The window quickly closed itself.

   Further analysis is required.


- Once we determine an alert needs further analysis, we will escalate the event to a senior incident handler for further review.

   - Return to your Sguil window.
   - Right-click **RT** in the status column.
   - Select **Update Event Status**.
   - Select **Escalate**.
   - Add a comment: "Trojan may have been downloaded."
   - Click **Okay**.

 Note: This will move the alert from the Real Time alerts queue to the Escalation queue.


![Escalation Pivot](Images/Escalate%20Pivot.png)

We can verify the escalated event by:
- Selecting the **Escalated Events** tab.
- Right-clicking on the event.
- Selecting **Event History**.
- Verifying the note that was entered by the junior analyst.

#### Summary

- This demonstration covered how to conduct investigations using various threat hunting techniques. We focused on a few of the many ways to start an investigation.  

- ESM (enterprise security monitoring) includes endpoint telemetry, host-based monitoring of system data that uses OSSEC collection agents to gather syslog data.

- To investigate network-based IDS alerts, security administrators must use enterprise security monitoring, which includes visibility into endpoint OSSEC agents.

- IDS alerts are snapshots in time. They raise questions that need answers. With the use of Security Onion, security admins can use PCAPs to reconstruct a crime.

### 07. Investigation, Analysis, and Escalation

- [Activity File: Investigation, Analysis, and Escalation](Activities/06_Investigation_Analysis_and_Escalation/Unsolved/README.md)


### 09. Review Investigation, Analysis, and Escalation Activity 


- [Solution Guide: Investigation, Analysis, and Escalation Activity](Activities/06_Investigation_Analysis_and_Escalation/Solved/README.md)

### 10. Threat Hunting - Cyber Threat Intelligence

Threat intelligence is important at every level of government and public sector organizations, which use it to determine acceptable risk and develop security controls that inform budgets.

Malicious actors have various motivations. For example:
- Hacktivist organizations are politically motivated.
- Criminal hackers are financially motivated.
- Cyber espionage campaigns, most typically associated with nation states, steal corporate secrets.

Knowing the motivations for attacks against your organization will help you determine the security measures necessary to defend against them.

#### Threat Intelligence Cards

As a member of the Computer and Incident Response Team (CIRT), one of your responsibilities is to establish a threat intelligence card, which documents the TTPs used by an adversary to infiltrate your network.

- When handling a large-scale intrusion, incident responders often struggle with organizing intelligence-gathering efforts.

- Threat intelligence cards are shared among the cyber defense community, allowing organizations to benefit from the lessons learned by others.

Cyber threat intelligence centers on the triad of actors, capability, and intent, along with consideration of TTPs, tool sets, motivations, and accessibility to targets.  

- These factors inform situational aware decision making, enhanced network defense operations, and effective tactical assessments.


### 11. Threat Hunting - Cyber Threat Intelligence 

- [Activity File: Threat Hunting - Cyber Threat Intelligence](Activities/09_Threat_Hunting/Unsolved/README.md)


### 12. Review: Threat Hunting - Cyber Threat Intelligence Activity 


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
