## Solution Guide: Containers

The goal of this activity was to configure your jump box to run Docker containers and to install a container.

---

1. Start by installing `docker.io` on your Jump box.

    - Run `sudo apt update` then `sudo apt install docker.io`

2. Verify that the Docker service is running.

    - Run `sudo systemctl status docker`

      - **Note:** If the Docker service is not running, start it with `sudo systemctl start docker`.

3. Once Docker is installed, pull the container `cyberxsecurity/ansible`.

    - Run `sudo docker pull cyberxsecurity/ansible`.

    - You can also switch to the root user so you don't have to keep typing `sudo`.

    - Run `sudo su`.


4. Launch the Ansible container and connect to it using the appropriate Docker commands.

    - Run `docker run -ti cyberxsecurity/ansible:latest bash` to start the container.

    - Run `exit` to quit.

5. Create a new security group rule that allows your jump box machine full access to your VNet.

    - Get the private IP address of your jump box.

    - Go to your security group settings and create an inbound rule. Create rules allowing SSH connections from your IP address.

       - Source: Use the **IP Addresses** setting with your jump box's internal IP address in the field.

        - Source port ranges: **Any** or * can be listed here.

        - Destination: Set to **VirtualNetwork**.

        - Service: Set to **SSH**

        - Destination port ranges: WIll default to port `22`.

        - Protocol: Will default to  **TCP**.

        - Action: Set to **Allow** traffic from your jump box.

        - Priority: Priority must be a lower number than your rule to deny all traffic.

        - Name: Name this rule anything you like, but it should describe the rule. For example: `SSH from Jump Box`.

        - Description: Write a short description similar to: "Allow SSH from the jump box IP."

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
