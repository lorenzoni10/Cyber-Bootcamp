## Homework File: Cloud Security

Congratulations! You have finished the cloud security portion of the course.

Your homework assignment will be 2 parts:

### Part 1

Cloud computing has many terms and definitions that are unique to the cloud. As such, it is important to understand and remember this jargon when speaking to potential employers or peers.

In part 1 of the homework, our goal is to solidify many of the terms and concepts you have learned throughout the last 4 weeks of class.

#### Instructions

Answer the following questions in your own words:

1. What are 3 common job roles that combine security and cloud skills?

2. What are the 3 biggest cloud provider platforms?

3. What are the 6 most common cloud services (and their acronyms)?

4. What is the difference between a virtual network and a physical network?

5. What is the point of setting your first firewall rule to block _all_ traffic?

6. What is the difference between physical computing components (CPU, RAM, HDD/SSD) and virtual computing components? 

7. What is the purpose of using an encrypted ssh key to connect to a machine?

8. What is the difference between a container and a virtual machine?

9. What is a provisioner? Provide 3 examples of common provisioning software.

10. What is meant by Infrastructure as Code?

11. What is Continuous Integration/Continuous Deployment?

12. What is a VPN and when should us use one?

13. What is the purpose of a load balancer?

14. What is a resource group in Azure?

15. What is Region in Azure?

### Part 2
#### Background

- During the last week, you created a highly available web server for XCorp's Red Team to use for testing and training.

- Your lead cloud administrator has asked for a diagram of the Network you created to keep for documentation and company records.

- Your task: Use [draw.io](https://app.diagrams.net/) to create a detailed diagram of your cloud infrastructure.

### Cloud Recap

When you're finished completing all the activities in cloud week, you should have:
- A total of 3 VMs running DVWA.

- All 3 VMs receiving traffic from your load balancer.

### Your Goal 

When you are finished with this assignment, you should have a network diagram that shows your entire cloud setup, including your Ansible jump box and the Docker containers running on each VM.

This document can be used as part of a portfolio to demonstrate your ability.

### Instructions

Use a free account at [draw.io](https://app.diagrams.net/) to diagram the entire cloud network you have created.

    - Your diagram should show the following:
        - Azure resource group
        - Virtual network with IP address range
        - Subnet range
        - Flow of specific traffic (e.g., HTTP, SSH)
        - Security group blocking traffic
        - Load balancer
        - All 4 VMs that you have launched 
        - Where Docker and Ansible are deployed

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
