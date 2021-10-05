## Activity File: Containers

- In the previous activities you created a secure network for XCorp's Red Team. You launched a virtual machine to be a jump box on that network, with a secure SSH connection. 

- In this activity, you will set up this machine to run containers and prepare it to configure other machines.

- You must configure your jump box to run Docker containers, and install a container.

### Instructions

1. Install `docker.io` on your jump box.

2. Verify that the Docker process is running. 
   - **Note:** If the Docker service is not running, start it with `sudo systemctl start docker`. 

3. Once Docker is installed, pull the container `cyberxsecurity/ansible`.
    - You will need to escalate your privileges to run the correct command.

    - If you get the error `failed to resize tty, using default size`, ignore it. 

4. Once you have the container, make sure you can launch it and connect to it using the appropriate Docker commands.

5. Return to Azure and create a new security group rule that allows your jump box machine full access to your VNet. You will need to complete the following:

    - Get the private IP address of your jump box from the VM resources page inside the Azure portal.

    - Go to your security group settings and create an inbound rule.
    - Create a rule allowing SSH connections from your jump box's internal IP address.
  
The rule should look similar to the following: 

- Source: Use the **IP Addresses** setting with your jump box's internal IP address in the field.

- Source port ranges: **Any** or * can be listed here.

- Destination: Set to **VirtualNetwork**.

- Service: Select **SSH**

- Destination port ranges: This will default to port `22`.

- Protocol: This will default to **TCP**.

- Action: Set to **Allow** traffic from your jump box.

- Priority: Priority must be a lower number than your rule to deny all traffic.

- Name: Name this rule anything you like, but it should describe the rule. For example: `SSH from Jump Box`.

- Description: Write a short description similar to: "Allow SSH from the jump box IP."

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
