## Activity File: Load Balancing

- Previously, you created a jump box on a secure VNet that you can use to run Ansible and configure other machines. You also used this jump box to configure another machine and set up DVWA for the Red Team to use.

- In this activity, you will continue with this setup of DVWA. It needs to be accessible from the internet, and we want to make sure it has high availability and some redundancy. 

- At this time, if the VM receives too much traffic from the Red Team, the server may stop responding (Denial of Service).

- You must install a load balancer in front of the VM to distribute the traffic across more than one VM.


### Instructions

1. Create a new load balancer and assign it a static public IP address.
	- Give the IP address a unique address name as it will be used to create a URL that maps to the IP address of the load balancer.

2. Navigate to the load balancer settings and install a health probe.

3. Using the load balancer settings, add your VMs to the backend pool.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
