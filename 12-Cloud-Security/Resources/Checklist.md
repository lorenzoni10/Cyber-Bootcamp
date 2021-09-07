## Cloud Lab Creation Daily Checklist

### Day 1

At the end of Day 1, you should have the following critical tasks completed:

- [ ] A total of three VMs created. One jump-box and two Web VMs.

- [ ] All three VMs are configured with the same SSH key.

- [ ] The SSH key being used does not have a password associated with the key.

  - To check that the SSH key has no password, run: `ssh-keygen -y -f ~/.ssh/id_rsa`.

  - If configured correctly, this command will print a fingerprint similar to the one below.
    
    ```bash
    $ ssh-keygen -y -f ~/.ssh/id_rsa
    ssh-rsa 0000B9N89aD1y892E0000D0Q0B000B0QDZ2m897aYvW89Qo2s0v2ajGViQgxWw0i5nyE89O8989gRfJ10QHaQhnKxUBQPkTX6/9+ykv6mKqFQPl9g7M6Suo2ISfadt+QLbskqJ89Oa8SgKykDRgL/0fgm4kRFDrFZ0U0FX71+D028LZDPNIQkYEygZMo8q7Dixl0KLSq+uGahNK9DZhPqRO2qdhxVTU52uQ289H8989RF+Oy1RnqQh89DM7UjKZubUU0K6x50DpTmF9+gBIpy2UWbgQ5KItuK5187NXvw8i89ybSoIXEq/NiqEFSaBEUW6Q2xDdSYUKJx6nsaD4WVSnS89U9TTlWSW64F2OWIaujULPUL5GWx6vDITEVNwblLP
    ```

  - However, if the user is prompted for a password, the key has been created incorrectly.

- [ ] Web VMs are created using the same availability set.

- [ ] Web VMs should have 2 GB of RAM.

- [ ] Jump-Box VM only needs 1 GB.

- [ ] All three VMs should have 1 vCPU .

- [ ] All VMs are using the same security group and vNet.

### Day 2

At the end of Day 2 , you should have the following critical tasks completed:

- [ ] Docker is installed and running on the jump-box.
  
  - To verify, run: `docker --version`.

- [ ] The `cyberxsecurity/ansible` Docker container is running on the jump-box.

  - To verify, run: `docker image ls | grep 'cyberxsecurity'`.  

  - You should receive an output similiar to the following:

    ```bash
      $ docker image ls | grep 'cyberxsecurity'
      cyberxsecurity/ansible                    latest              30b40da30088        6 months ago       174MB

    ```
  - If the command fails, install the image with: `docker pull cyberxsecurity/ansible`.

- [ ] The security group has a rule that allows the jump-box SSH access to the vNet.

  - To verify:

    - Navigate to the [Azure Portal](https://portal.azure.com).
    - Search for **Virtual Machines**.
    - Click on the **Jump Box** in the list of VMs.
    - In the left pane, find **Security Groups**.
    - Verify that the correct rule is set.

  - If the rule is missing, repeat the steps in  **07. Review Jump Box Administration**.

- [ ] An SSH key created from inside the Ansible container that has no password.

   - To check that the SSH key has no password, first attach to the container by running `docker attach <container name>`
  
   - Then run `ssh-keygen -y -f ~/.ssh/id_rsa`.
  
   - If this command fails or prompts for a password, repeat the steps in section **07. Review Jump Box Administration**.


- [ ] The Web VM's password has been reset using the SSH key from the Ansible container.

   - To verify that the web VMs use SSH instead of password authentication, connect via SSH using the appropriate key: `ssh -i ~/.ssh/<NAME OF KEY> <USERNAME>@<WEB VM IP ADDRESS>`.

   - If the connection fails, repeat the steps in  **14. Review Provisioning Activity**.

- [ ] Ansible is able to make a connection to both Web VMs.

  - To verify connectivity, follow the steps below:

    - SSH into the Ansible VM: `ssh -i ~/.ssh/<NAME OF KEY> <USERNAME@Ansible VM IP Address>`
    - Ping the Web VMs: `ping <Web VM IP Address>`
    - If the ping test fails, repeat the steps in **14. Review Provisioning Activity**.

## Day 3

At the end of Day 3, you should have the following critical tasks completed:

- [ ] An Ansible playbook has been created that configures Docker and downloads a container.

    - To verify, check that the file `/etc/ansible/ansible-config.yml` exists within the Ansible container.

    - The file should contain the same contents as the solution yml file here: [ansible-config.yml](../3/Activities/03_Ansible_Playbooks/Solved/ansible-config.yml).

- [ ] The Ansible playbook is able to be run on the Web VMs.

    - To verify, run: `ansible-playbook /etc/ansible/ansible-config.yml`.

    - If this command fails, repeat the steps in  **04. Review Ansible Playbooks Activity**.

- [ ] The Web VMs are running a DVWA Docker container.

    - To verify, connect to the Web VM via SSH: `ssh -i ~/.ssh/<Name of SSH Key> <username>@<Web VM IP Address>`

    - Then, run: `docker ps`. You should see output like below.
      ```bash
      $ sudo docker ps
        CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
        21a0f55d4e30        cyberxsecurity/dvwa        "bash"              6 weeks ago         Up 3 seconds      
      ```
    - If no DVWA container is running, repeat the steps in  **04. Review Ansible Playbooks Activity**.

- [ ] A load  balancer has been created and at least two Web VMs placed behind it.
    - To verify:

      - Navigate to the [Azure Portal](https://portal.azure.com).

      - Search for **Load Balancers**.

      - Select the load balancer created for the exercise from the list.

      - Select **Backend Pool**.

      - Verify that the Web VMs have been placed in the pool.

      - Make sure that the Security Group is allowing traffic to the load balancer. (Remove the deny all rule)

    - If any of the above steps have not been completed, repeat the solution in **07. Load Balancing Activity**.

- [ ] The DVWA site is able to be accessed through the load balancer from the internet.

  - From a command line on your personal computer, run: `curl <Public IP of DVWA Site>`.

  - If this command fails, review the steps in  **10: Review Security Configuration**.
  
  - Be sure to run the `curl` command from a machine that has been whitelisted for access to the target VM!

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

