## Unit 12 README: Cloud Security and Virtualization

### Unit Description

The Cloud Security and Virtualization unit will introduce cloud computing service models, cloud networking, firewalls, and virtual computing.

Over the next four classes, we will build a basic cloud network using VMs and containers.

### Unit Objectives

<details>
    <summary>Click here to view the daily unit objectives.</summary>

  <br>

- **Day 1:** Introduction To Cloud Computing

    - Distinguish between cloud services and identify an appropriate service depending on an organization's needs.

    - Set up a virtual private cloud network.

    - Protect their cloud network with a firewall.

    - Deploy a virtual computer to their cloud network.

- **Day 2:** Cloud Systems Management

    - Access their entire VNet from their jump box.

    - Install and run containers using Docker.

    - Set up Ansible connections to VMs inside their VNet.

- **Day 3:** Load Balancing and Redundancy

    - Write Ansible playbooks to configure VMs.

    - Create a load balancer on the Azure platform.

    - Create firewall and load balancer rules to allow traffic to the correct virtual machines.

- **Day 4:** Testing Redundant Systems

    - Verify redundancy by turning off one or more virtual machines used in the infrastructure

    - Can be used as a catch-up day to finish activities from the previous days in Cloud Security.

</details>


### Lab Environment

For the majority of demonstrations and activities, the class will use Microsoft Azure cloud services and the Azure cloud portal.

- You will **not** be using any of the Azure lab environments. Instead, you will be using personal Azure accounts.

- You should have already created a free account on [Microsoft Azure](https://azure.microsoft.com/en-us/) **before** the beginning of class. Please make sure you are signed into your own personal Azure account and **not** the lab environments.

- Refer to the the [Setup Guide](https://docs.google.com/document/d/1gs_09b7eotl7hzTL82xlqPt-OwOd0aWA78qcQxtMr6Y/edit) and [Azure Free Tier FAQ's](https://azure.microsoft.com/en-us/free/free-account-faq/) if needed.

### What to Be Aware Of:

- :warning: **Heads Up** : This week is a cumulative lesson. Each day's work builds on the previous day. Therefore, you cannot miss a day and continue on to the next lesson without getting caught up. If you miss one of the four days, you will need to let the instructional staff know so they can help you prepare.

- **Important:** During these classes, you will need to generate SSH keys. Please remind any students that are using a Windows machine that they should have downloaded and installed [GitBash](https://gitforwindows.org/) on their machine. GitBash should be used to follow all SSH instructions for these units.


### Security+ Domains

This unit covers portions of the following domains on the Security+ exam:

<details>
    <summary> 2.0 Architecture and Design and 3.0 Implementation
 </summary>
 <br>

- Web server
- Application server
- Network infrastructure devices
- Firewalls
- Proxies / VPNs
- Load Balancers
- Network Segmentation/Isolation
- Continuous integration
- Immutable systems
- Infrastructure as code
- Cloud deployment models
- Hypervisor
- Continuos Monitoring
- Redundancy
- High availability


</details> 

<br>

For more information about these Security+ domains, refer to the following resource: [Security+ Exam Objectives](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-security-sy0-601-exam-objectives-(2-0).pdf?sfvrsn=8c5889ff_2)




### Additional Reading and Resources

<details> 
<summary> Click here to view additional reading materials and resources. </summary>
</br>

These resources are provided as optional, recommended resources to supplement the concepts covered in this unit.

- [Microsoft Azure](https://azure.microsoft.com/en-us/)
- [Azure Documentation](https://docs.microsoft.com/en-us/azure/?product=featured)
- [Docker](https://www.docker.com/)
- [Docker Documentation](https://docs.docker.com/)
- [Ansible](https://www.ansible.com/)
- [Ansible Documentation](https://docs.ansible.com/)
- [YAML](https://yaml.org/spec/1.2/spec.html#Introduction)

</details>

---

### Unit 12: Homework Assignment

This unit's homework assignment can be viewed here: 

- [Unit Homework File](Homework/Unsolved/README.md)

### Looking Forward 

Next week, we will begin our first project. The web servers that you setup during the cloud unit will be used during the project to feed logs into a server running an ELK stack. These logs will then be viewed and analyzed using Kibana.

---


© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
