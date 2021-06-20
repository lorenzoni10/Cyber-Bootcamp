## Activity File: Disaster Recovery Planning For GeldCorp

* In this activity, you will continue to work in groups to create a high-level disaster recovery plan for GeldCorp.

* A full DR plan is a multiphase project that can take several weeks to complete. For this activity, you will focus on some of the high-level details.

* The goal is to think like a security professional and get a better understanding of the complexities involved in DR planning.

### Instructions

In this activity, you'll develop a high level DR plan for GeldCorp. The DR plan should focus on the network and technology domains of the business, and be designed for situations where the business suffers a catastrophic incident that must be contained before operations can continue.  

When thinking about the DR plan, assume that a major disruption has occurred, resulting in the loss of the main data and tech center for the company. 

1. Use the below information about GeldCorp and reference the information from the [Threat Modeling activity](../../../2/Activities/03_Threat_Modeling/Solved). Read it thoroughly. It is up to you to determine which pieces are relevant for your specific plan. 

    - **Physical Environment**

      - All office buildings have one main door and two secondary (back) doors.

      - Each door has card access, but GeldCorp still experiences occasional tailgating.

      - Servers at the data centers are on the main floor of each office, which is accessible from all wings of the building.

    - **Personnel**

      - Aside from security culture training, none of the employees have any exposure to information security.

      - Technical employees and executives sometimes work remotely.

      - Technical employees and executives are given administrator accounts by default.

      - Employee turnover is high.

    - **Network**

      - GeldCorp has both wired and wireless networks.

      - Visitors can connect to the guest network at the office. Employees often use this network.

      - Employee workstations and laptops have VPN access to the corporate intranet.

    - **Technology**

      - The company buys hardware and software and deploys them with default configurations.

      - Some software applications are built internally by an in-house software development team.

      - Each site on the corporate intranet requires employees to login, and sometimes different internal sites require a different login credentials.

      - The company has experienced consistent virus and malware infections, due largely to phishing attacks.

      - The company allows employees to connect their own devices to the office wireless networks.

    - **Security**

      - GeldCorp has yet to implement your formal security policy recommendations. Currently, they have none.

      - The company has experienced DDoS attacks in the past.

      - No formal process exists for handling field issues or security incidents.

2. Write a **policy statement** (1-2 paragraphs):

    - Detail how the business would be affected in the event of a disastrous breach.

    - What are the main objectives of the disaster recovery plan for GeldCorp?

3. Write a **plan overview** including the following the information below. You do not need to do a thorough BIA analysis. Be creative using what you know about GeldCorp.
    - MTD for information systems.
    - RTO for information systems.
    - RPO for information systems (i.e frequency of data and other systems backup).
    - Backup strategies that should be implemented.
    - Details for at least one of the following sites, which senior management will need to be aware of, and recommended activation procedures: 
      - Cold Site 
      - Warm Site 
      - Hot Site 

    - Explain how the business should prioritize its resources to recover from the reputational and operational damage of a catastrophic loss. Include any people from the company you feel should be involved in this.

4. Answer the following questions about **plan implementation and testing**:

    - What will you need to do to implement your disaster recovery plan? Which stakeholders need to be involved? 

    - How will you train your employees and how you will test critical details of the plan? Be specific.

       - **Hint:** Use what you learned while developing a training plan for a security culture framework to design the training and implementation for your DR plan.
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
