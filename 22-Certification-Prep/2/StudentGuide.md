## 22.2 Student Guide: Security+

### Overview

In today's class, we will dive deeper into the domains covered by the Security+ exam. 

### Class Objectives

By the end of class, you will be able to:

- Explain how each domain is divided across the Security+ exam.

- Prepare for Security+ questions from domains and topics we have not explored in the curriculum, such as Architecture and Design and Identity and Access Management.

- Correctly answer Security+ practice questions. 

### Slideshow

The lesson slides are available on Google Drive here: [22.2 Slides](https://docs.google.com/presentation/d/1zdBE1qP5k7i9tK3C44jVeoGLqn17OJAtwIU2NFzA-E0/edit)

-------

### 01. Welcome and Overview 

Today we will continue to prepare for the Security+ exam.

The topcis taught in the last class include:

- There are over 300 information security certifications from over 40 issuing organizations.

- These certifications are broken into three types: beginner certifications, advanced certifications, and specialized certifications.

- Information security professionals take different certification paths depending on what they are interested in.  
- One of the most popular beginner certifications is Security+.

  - One of the best methods to prepare for the Security+ exam is the CertMaster Practice tool, which you will have access to.

The first half of today's class will focus on several domains on the exam and the types of questions they contain. The second half of the class will be a fun quiz competition using a program called Kahoot.



### 02. Security+ Identity and Access Management Domain

The Security+ exam consists of the following five domains:
- 1.0 Attacks, Threats, and Vulnerabilities
- 2.0 Architecture and Design 
- 3.0 Implementation
- 4.0 Operations and Incident Response
- 5.0 Governance, Risk, and Compliance 
  
Here is a breakdown of the domains by percentage: 

- 1.0 Attacks, Threats, and Vulnerabilities -  24%
- 2.0 Architecture and Design -  21%
- 3.0 Implementation -  25%
- 4.0 Operations and Incident Response  - 16%
- 5.0 Governance, Risk, and Compliance  - 14%


While there were many topics that were covered across these domains, there are several subdomains on the exam were outside the scope of this boot camp. 

- Therefore, we will review some of the types of questions you may see on the Security+ exam from these subdomains


#### Identity and Access Management

We will first cover types of questions you may see covering the topic of identity and access management.

Identity and access management covers the security policies that ensure that an organization's resources are only accessible by the right people, for the right reasons, at the right times.
  
There are significant risks to incorrectly assigning access to resources.
  - For example, if an organization gives all staff access to payroll databases, they would be able to view PII and other private data of the organization and its employees. 

Across the different domains, there are several subdomains that contain questions covering IAM.

1. **2.4 - Summarize authentication and authorization design concepts.**

    - This subdomain focuses on the basic terms and concepts associated with IAM such as:
      - **Authentication, Authorization, and Accounting (AAA)**: The framework to best control access to an organization's resources.
      
        - Types of authentication factors:

          - Something you are: This includes biometrics, such as retina scanning or facial recognition.

          - Something you have: Such as tokens or key cards.
          
          - Something you know: Such as PINs and passwords.
      
  
        ``` 
        Of the following authentication factors, which one is a different factor than a retina scan?
          (A) Hand geometry recognition
          (B) Voice recognition
          (C) Fingerprint recognition
          (D) Proximity cards 
          ```
  
        - The correct answer is D.
          - Proximity cards are "something you have" while the other options are all biometric factors ( "something you are").
  
2. **3.8 - Given a scenario, implement authentication and authorization solutions.**

    - This subdomain focuses on the the application of the concepts associated with IAM, such as authentication protocols like Kerberos, CHAP, and PAP.
        - **Kerberos** is an authentication protocol developed at MIT that uses tickets.

        - **Password Authentication Protocol (PAP)** uses a standard username and password to authenticate to a remote system. It is considered insecure. 

        - **Challenge-Handshake Authentication Protocol (CHAP)** uses a three-way handshake, making it more secure than PAP.

    
        ```
        Which of the following authentication protocols is considered insecure due to its lack of encryption?
          (A) EAP
          (B) SAP
          (C) PAP
          (D) CHAP
        ```
    
        - The correct answer is C. PAP is insecure and unencrypted. 


   - This subdomain also focuses on the management decisions to make sure the right people have access to the right resources for the right reasons. 
    - Various types of access controls include:
      - **Mandatory Access Control (MAC)**
      - **Discretionary Access Control (DAC)**
      - **Role Based Access Control (RBAC)**

   - This topic also focuses on selecting the most optimal access controls based on your organization's environment.

      - For example, voice recognition is an appropriate biometric control if your office environment is relatively quiet.
    

        ```
        For the following biometric controls, which would you select if you have a noisy office with good lighting and need a cost-efficient solution?
          (A) Voice recognition
          (B) DNA analysis
          (C) Fingerprint recognition
          (D) Speech recognition
        ```
  
      - The correct answer is C. A and D would not be optimal in a noisy office and B would likely be an expensive biometric solution.

        - For the difference between voice and speech recognition,  voice recognition detects speakers based on the characteristics specific to the person, while speech recognition detects the words, absent of any unique accents, inflections, or characteristics of the speaker. 

        - Speech recognition is "what was said" and voice recognition is "who said it." 


   - This subdomain also focuses on how user accounts are managed, such as the concept of least privilege, which you should be familiar with. 
      - This is the principle that an individual or system should be given the minimum access rights needed to complete their tasks.

    - Account types:
      - User accounts: The basic, standard account type of users at your organization. These accounts are usually limited in privileges.

      - Guest accounts: Allow non-employees to have limited access to your organizations resources.

      - Privileged accounts: Have greater access than user accounts and are provided to managers and system administrators.
    
      
        ```
        You have an an external auditor that needs limited access to your organization. What type of account should you provide them?
            (A) Guest Account
            (B) User Account
            (C) Sudo Account
            (D) Service Account
        ```  
        
       - The correct answer is A. You would provide a guest account to a non-employee who needed limited access.
     
In the next activity you will get an opportunity to take a mini quiz on several multiple-choice and PBQ questions from these topics.
 

### 03.  Security+ Identity and Access Management 

- [Google Form: Identity and Access Management Quiz](https://forms.gle/wxtZpELtv33i5StV8)
  
  
### 04. Security+ Architecture and Design Domain 


In this section we will look at the Security+ Architecture and Design domain, as there were several subdomains not covered in our class

#### Security+ Architecture and Design

Architecture and Design covers the processes and controls used to protect the confidentiality, integrity, and availability of an organization's data.

Within the Architecture and Design domain are eight subdomains: 

1. Explain the importance of security concepts in an enterprise environment.
2. Summarize virtualization and cloud computing concepts.
3. Summarize secure application development, deployment, and automation concepts. 
4. Summarize authentication and authorization design concepts.
5. Given a scenario, implement cybersecurity resilience.
6. Explain the security implications of embedded and specialized systems. 
7. Explain the importance of physical security controls. 
8. Summarize the basics of cryptographic concepts.


Note that while it is important to be familiar with all eight subdomains, this section will focus on three subdomains that have not been covered in our course: #3, #6,  #7

#### Subdomain 3: Summarize secure application development, deployment, and automation concepts.

  - This subdomain focuses on the concepts and processes relevant to developing secure applications for organizations and their users.
  - Some terms that you should be familiar with include:
    - **Input Validation**: Restricts what data can be input to application fields, such as limiting non-ASCII characters.

    - Software development methodologies:
      - **Agile**: A flexible development method that allows changes to the development requirements.

      - **Waterfall**: A structured and rigid development method where each step of development cycle is dependent on the previous steps.
    
  
    ```  
    What is the biggest risk of outputting detailed application errors with coding details?
      
      (A) There is no risk, and it is recommended.
      (B) Coding details could provide the developer's name.
      (C) Coding details could illustrate vulnerabilities in the application code, which a hacker can then exploit.
      (D) Coding details could show when the code was written.
    ```
  
    - The correct answer is C. Displaying the code details, such as the coding language, version, and structure, could provide vulnerability information for hackers to exploit.




#### Subdomain 6:  Explain the security implications of embedded and specialized systems.

  - This subdomain focuses on the security of systems that have hardware with software embedded within them.

    - A smart refrigerator is an example of an embedded system. A smart refrigerator has hardware and software embedded within it to complete specific tasks, such as monitoring temperature and determining if a filter needs replacing.


  - You should become familiar with the following terms:
    -  **Supervisory Control and Data Acquisition (SCADA)**: A system used to control technical equipment in industries such as energy, oil, and water management.

    - **Internet of Things (IoT)**: The network of devices that are connected to the internet, which are considered an extension of the internet itself. These devices include smart light bulbs, smart refrigerators, printers, and door locks.
      - IoT is an expansive term relevant to many areas, such as smart houses, research and monitoring in the healthcare industry, wearable devices such as step counters, data collection in agriculture, manufacturing, and city management, and many, many more. 
    
      
        ``` 
        To protect their data, which type of systems are usually not connected to the internet?
          (A) Linux servers
          (B) Apache web servers
          (C) SCADA systems
          (D) Home office networks
        ```
  
       - The correct answer is C. While there are some SCADA systems that have limited connection to the internet, because they run high impact systems they usually are not connected.
  


#### Subdomain 7: Explain the importance of physical security controls. 

  - This subdomain focuses on concepts associated with physical security processes and controls.

  - Terms you should become familiar with include:
    - **Environmental controls**: For example, HVAC systems and fire suppression systems.
    
    - **Physical access controls**: For example, man traps and security guards.
    
    - **Physical control types**: For example:
      - **Deterrents**, such as alarms.
      - **Preventions**, such as locks or gates.
    
  
    ```
    What type of risk can a bollard protect against?

      (A) Fire
      (B) Flooding
      (C) Vehicle access
      (D) Script kiddies
     ```
  
    - The answer is C. A bollard is a short post built into the ground to protect areas from vehicle access.
     
In the next activity, you will take a mini quiz with several multiple choice and PBQ questions from the Architecture and Design domain.
 

### 05. Security+ Architecture and Design Quiz 

- [Google Form: Architecture and Design Quiz](https://forms.gle/1AT2r9qY2xsyAcJj7)


  
-------
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  

