## Activity File: Ansible Playbooks

- Previously, you created a secure network and connection to a VM that you can use as a jump box to configure other machines on the Red Team network. 

- In this activity, you will use Ansible to configure the VM and install Docker, as well as the web application they will use for testing and training.

- Your task is to create an Ansible playbook that installs Docker and configures a VM with the DVWA web app.

### Instructions

1. Connect to your jump box, and connect to the Ansible container in the box. 

2. Create a YAML playbook file that you will use for your configuration. 

    - Use the Ansible `apt` module to install `docker.io` and `python3-pip`.

    - Use the Ansible `pip` module to install `docker`.

    - Use the Ansible `docker-container` module to install the `cyberxsecurity/dvwa` container.
      
		- Make sure you publish port `80` on the container to port `80` on the host.
		
		- Can you find a way to make sure the container is restarted every time you restart the VM?
    
    - Use the Ansible `systemd` module to make sure that the docker service is started when the VM restarts. 

3. Run your Ansible playbook on the new virtual machine. 

4. To test that DVWA is running on the new VM, SSH to the new VM from your Ansible container.
    - Run `curl localhost/setup.php` to test the connection. If everything is working, you should get back some HTML from the DVWA container.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
