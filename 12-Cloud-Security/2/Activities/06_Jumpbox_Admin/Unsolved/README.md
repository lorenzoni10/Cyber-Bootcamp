## Activity File: Jump Box Administration

- In the previous activity, you have created a secure network for XCorp's Red Team and launched a virtual machine on that network. 

- In this activity, you will configure this machine as a jump box that you will connect to and use to configure other machines that will be added to the Red Team's network.

- At this time, you are not able to connect to your VM because your security group settings are blocking all connections.

- You must log into portal.azure.com and create a new security group rule to allow SSH connections only from your current IP public address. Then, connect to your new virtual machine for management.

### Instructions

1. Start by identifying your public IP address.
   - If you are unsure of your IP address, open the terminal and enter the command `curl icanhazip.com`. You can also google "Whats my Ipv4 address."
	 - Make sure you get your IPv4 address and not your IPv6 address.
	 - Note that if you connect to the internet from another location, this rule will need to be updated if you would like to connect from that new location. 
	 - Note also that your home network IP address _may_ change at some point, in which case you will need to update this rule with your new IP.

Next, log into portal.azure.com and complete the following:

2. Locate the network security group that you created in the last class and click on it.

3. Create a rule to allow SSH connections from your current public IP address to your VM's internal IP address. 

   - In the configuration settings, select **Inbound security rules** on the left panel. 

   - Makes sure to set a priority level lower than your rule to deny all traffic. 

	 - Limit traffic from your external IP address and to only the internal IP address of the Jump-Box.

	**HINT:** Remember that the source port is chosen at random when a system attempts to make a connection. Because the source port cannot be known before you start a connection, always set the source port to '*' or 'Any'.

4. On the command line, SSH into your VM for administration. Windows users should use GitBash.

   - The command to get connected is `ssh username@VM-public-IP`. 

   - Replace `username` with the username that you set up, and replace `VM-public-IP` with the IP address of your Azure VM. This is listed on the Overview page of your VM. 

5. Once you are connected, check your `sudo` permissions.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 