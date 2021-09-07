## Activity File: Redundancy

**NOTE:** This Activity is optional. You may not be able to create a 3rd VM in the same region due to availability in Azure. If that is the case, this activity can be skipped.

This activity can also be skipped if you need a bit more time to complete all of the previous steps thus far.

- Previously, you used your jump box to configure 2 VMs before creating a load balancer and placing the VMs behind the load balancer.

- In this activity, you will continue to configure your Red Team cloud setup by configuring a new VM to add to the load balancer backend pool.

- You must create a copy of your VM using Ansible for the configuration and place it in the backend pool for your load balancer.

### Instructions
1. Launch a new VM in the Azure portal.
    - Name this VM: `web-3`.

    - For your Availability set, choose RedTeamAS.

		- Make sure the VM does not have an external IP address.

		- Add the VM to your security group.

    - Be sure to use the same admin name and SSH key (from your Ansible container) that you used for the current DVWA machines.

    - You may need to login to the Ansible container on your jump box to get your key again.

2. Once your machine is set up, connect to the Ansible container on your jump box and test the Ansible connection using SSH.

3. Add the new VMs internal IP address to your Ansible configuration.
	- Remember to add `ansible_python_interpreter=/usr/bin/python3`

4. Test your configuration using the Ansible `ping` command.

5. Run your Ansible playbook to configure your new machine.
 
    **Hint**: If you run your playbook, it will run on both machines. Ansible will recognize your original VM and check its settings. It should only make changes to the new VM.

6. When the Ansible playbook is finished running, SSH to your new VM and test the DVWA app using `curl`.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
