## Activity File: Security Configuration

- Previously, you configured a DVWA VM from your jump box VM and placed it behind a load balancer. At this time, you still cannot access the DVWA site.

- In this activity, you will continue with the setup of this training environment and allow DVWA to be reached from your home IP Address.

- Your task is to configure the load balancer and security group to work together to expose port `80` of the VM your Home IP address.

### Instructions

1. Create a load balancing rule to forward port `80` from the load balancer to your Red Team VNet.

    - Set **Session persistence** to **Client IP and protocol**.

2. Create a new security group rule to allow port `80` traffic from the public IPv4 address of your workstation to your internal VNet.
    **Hint**: This rule should only allow traffic from the network you are currently using to reach the subnet. If you change locations and connect to a different wifi, you will need to update this rule to allow your connection. Remember you can google `what's my IPv4` to get your public IPv4 address.

3. Remove the rule that blocks **all** traffic on your vnet in order to allow traffic from your load balancer through.

    - **Note**: All of your VMs should be using the same network security group. If, by accident, some VMs have their own network security group, you will need to add rules for each one to allow traffic on port 80.

4. Verify that you can reach the DVWA app from your browser.
    - **HINT** Open a browser and navigate to the _public IP Address_ of the load balancer, appended with `/setup.php` i.e. `http://207.53.45.xx/setup.php`
    - If everything is working, you should see the setup page for `DVWA`. If you are not getting through, troubleshooting will be needed.

#### Troubleshooting:
- Typically, if traffic is not getting through, it is an issue with the security group rules.
- Make sure that the `DVWA` containers are running on each of the VM's in your backend pool.
    - SSH to a VM directly from your jump box's Ansible container and check that the container is running:
        - Run `docker ps` to check for a docker container running.
        - Run `curl localhost` to check see if you get back `HTML` from the container.
- Use `nmap` to test a connection and port.
    - Run `nmap -Pn <public.IP.of.loadbalancer> -p 80`
        - A response of `filtered` indicates that the security group is blocking the traffic
        - A response of `open` indicates that traffic is reaching the load balancer and VM's.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
