##  19.3 Student Guide: Masters of the SOC

### Overview

Today, you will work in groups to become Masters of the SOC. You will use the skills you've acquired over the last two weeks to identify an organization's security issues.


### Slideshow

The lesson slides are available on Google Drive here: [19.3 Slides](https://docs.google.com/presentation/d/1xDogqc7WPmWwF9Q2d7ZZV0E9V7Sl_V0BicuQzLdeDaE/edit)

---

### 01. Introduction to Master of the SOC 

Today we will review many of the concepts we've learned about SIEM and Splunk with an engaging and fun activity called the Master of the SOC.

You will be broken up in groups of three or four and play the role of SOC analysts at a fictional organization.
  
- **Part 1: Create Your SOC**
  - You'll be provided logs of normal business activity for the fictional organization.

  - You'll be tasked with analyzing these logs and using them to create reports, alerts, and dashboards.

  - Specific instructions will be provided.
    
- **Part 2: Defend Your SOC**   
  - You'll be provided multiple sets of logs that contain suspicious activity.

  - You'll use the monitoring tools created in Part 1 to analyze and protect the organization from potential attacks.


### 02. Master of the SOC Scenario and Guidelines

#### Scenario

  - Each group will act as a SOC analyst at a small company called Virtual Space Industries (VSI).

  - VSI is a company specializing in the design of virtual reality programs for businesses.

  - VSI has heard rumors that a competitor, JobeCorp, may be launching cyberattacks to disrupt VSI's business.

  - As SOC analysts, you are tasked with using Splunk to monitor against potential attacks on your systems and applications.

  - Your Networking team has provided you with past logs to help you develop baselines and create reports, alerts, and dashboards.

  - After you have designed your monitoring solutions, you will be provided logs of attacks from JobeCorp and will determine if your monitoring solution successfully identified the attacks.
  
#### Guidelines    

- Groups will be provided two VSI logs files of normal, unsuspicious activity:
    - One for a Windows server
    - One for an Apache web server

- Use the Splunk Search & Reporting application. Do not not the Enterprise Security Application for this part.

- In each group, **each individual student** should be working in their own Splunk environment to conduct the activities.
    - Groups can split up activities between the different group members.

- One student in each group should have the "Master" Splunk SOC environment that contains all of the deliverables.

- The group must complete all required deliverables. Each group must decide how the SOC is designed and how the deliverables are achieved.

- Groups can use any resource while completing the activity: class notes, slides, Splunk online resources, etc.  
  
- If time permits, several groups can present their SOC at the end of class.   

### 03. Activity: Part 1 - Create Your SOC
  
  - [Activity File: Part 1 - Create Your SOC](activities/Part-1/Unsolved/README.md)
    - [Windows Server Logs](resources/windows_server_logs.csv)
    - [Apache Web Server Logs for Customer-Facing Web Application](resources/apache_logs.txt)

- [Solution Guide: Part 1 - Create Your SOC](activities/Part-1/Solved/README.md)
      
### 04. Break 

### 05. Activity: Part 2 - Scenario and Guidelines

In the first half of class, you designed several monitoring solutions to protect VSI.

- Unfortunately, VSI experienced several cyberattacks, likely from their adversary JobeCorp.

- Fortunately,  your SOC team recently set up several monitoring solutions to help VSI quickly identify what was attacked.

- These monitoring solutions will also help VSI create mitigation strategies to protect the organization.
  
Before beginning Part 2, review the guidelines again: 

- Groups will be provided two VSI logs files of normal, unsuspicious activity:
    - One for a Windows server
    - One for an Apache web server

- Use the Splunk Search & Reporting application. Do not not the Enterprise Security Application for this part.

- In each group, **each individual student** should be working in their own Splunk environment to conduct the activities.
    - Groups can split up activities between the different group members.

- One student in each group should have the "Master" Splunk SOC environment that contains all of the deliverables.

- The group must complete all required deliverables. Each group must decide how the SOC is designed and how the deliverables are achieved.

- Groups can use any resource while completing the activity: class notes, slides, Splunk online resources, etc.  
  
- If time permits, several groups can present their SOC at the end of class.   

**Important**: Since you are analyzing a new set of data, after the new data file is loaded, *the source must be changed* on the reports, alerts, and dashboards.
      
### 06. Activity: Part 2 - Defend Your SOC
  
  - [Activity File: Defend Your SOC - Part 2](activities/Part-2/Unsolved/README.md)
   - [Window Server Attack Logs ](resources/windows_server_attack_logs.csv)
   - [Apache WebServer Attack Logs](resources/apache_attack_logs.txt)
    
  
### 07. Activity Review:  Part 2 - Defend Your SOC 

- [Solution Guide: Part 2 - Defend Your SOC](activities/Part-2/Solved/README.md)
 
This week's homework is a continuation of today's activities, focusing on how to mitigate against the attacks they identified.
   
-------

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
