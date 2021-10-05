## Homework File: Cloud Security

### Background

- During the last week, you created a highly available web server for XCorp's Red Team to use for testing and training.

- At this time, that setup is only located in one data center (Availability Zone) within Azure's services. This means that if that data center has a problem, the site may go offline, even with multiple servers behind the load balancer. 

Read more about Availability Zones at [Microsoft Azure Documentation: Availability Zones](https://docs.microsoft.com/en-us/azure/availability-zones/az-overview).

### Your Goal 

- You must create two more VMs that are configured the same way as your existing VMs, and place them behind the same load balancer. 

- However, you must put them in two different Availability Zones within Azure. Be aware that these zones will exist in the same region.

When you're finished, you should have:
- A total of four VMs running DVWA across at least three Azure Availability Zones.

- All four VMs receiving traffic from your load balancer.

- A network diagram that shows your entire cloud setup, including your Ansible jump box and the Docker containers running on each VM.

### Instructions

1. Create two new VMs in different Availability Zones. 

    ![](../Images/Availability-Zone.png)

    - Name these VMs `DVWA-VM3` and `DVWA-VM4`.
    
    - Give them the SSH key and admin account from your Ansible container.

    - Add their internal IP addresses to your Ansible configuration.

    - Confirm you can connect to them using Ansible. 

    - Run your Ansible playbook to configure all four machines. 

2. Create a new load balancer that has the standard setting for SKU and the zone redundant setting for Availability Zone.

    ![](../Images/Zone-redundant.png)
    
    - Remove your VMs from the backend pool of your first load balancer.

    - Place all four behind your zone redundant load balancer.

3. Test that this setup is working by turning off the two VMs located in Availability Zone 1.

4. Use a free account at [gliffy.com](https://www.gliffy.com/) to diagram the entire cloud network you have created.

    - Your diagram should show the following:
        - Azure resource group
        - Virtual network with IP address range
        - Subnet range
        - Flow of specific traffic (e.g., HTTP, SSH)
        - Security group blocking traffic
        - Load balancer
        - All five VMs that you have launched 
        - Where Docker and Ansible are deployed
        - Availability Zones

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
