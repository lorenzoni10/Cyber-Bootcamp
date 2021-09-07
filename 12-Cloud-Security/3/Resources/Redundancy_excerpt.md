### 12. Instructor Do: Redundancy (0:05)

Welcome the students back from break and let them know that the next step in our cloud setup is to configure a new VM and place it behind the load balancer.

Explain that this provides **redundancy** for our DVWA server. A redundant setup means having a few exact copies of something. If one server goes offline, the other server will continue to host the website. 

- Multiple servers are often used in a setup like this. The more servers you use, the more resilient the website.

- Setting up a third server will complete our highly available setup. If the Red Team takes down one server, the other servers will step in to serve the website.

- This is the type of setup that many modern websites use to stay up and running at all times. 

Point out that the students have all the knowledge to complete this task.

Go over the high-level steps:

1. Get their SSH key from the Ansible container on their jump box.

2. Create a new VM using that key and the same admin name they used on the first VM.

3. Edit their Ansible configuration to include the new VM.

4. Use Ansible to configure the new VM with a DVWA container.

5. Place the new VM behind the load balancer.

Ask the students if they have any questions about any of these steps.

### 13. (Optional) Student Do: Redundancy (0:40)

**:warning:** This activity is optional. Students may not be able to create a 3rd VM in the same region. If they cannot, this activity can be skipped.

This activity can also be skipped if the class needs a bit of time to complete all of the needed steps thus far.


Explain the following to students:

- Previously, you used your jump box to configure 2 VM's before creating a load balancer and placing the VM behind the load balancer.

- In this activity, you will continue to configure your Red Team cloud setup by configuring a new VM to add to the load balancer backend pool.

- You must create a copy of your VM using Ansible for the configuration and place it in the backend pool for your load balancer.

:globe_with_meridians: Students should stay in the same **breakout room** groups as the previous activity.


Send students the following files:

- [Activity File: Redundancy](Activities/13_Redundancy/Unsolved/README.md)

### 14. Instructor Review: Redundancy Activity (0:15)

:bar_chart: Run a comprehension check poll before reviewing the activity. 

The goal of this activity is to add another VM to their backend pool with the exact same configuration as their first two VMs.

Students needed to create a copy of their VM using their Ansible playbook for the configuration and then place the VM in the backend pool for the load balancer.

Send students the following file: 

- [Solution Guide: Redundancy](Activities/13_Redundancy/Unsolved/README.md)

#### Walkthrough 

Explain that you will start by launching a new VM in the Azure portal.

- Be sure to use the same admin name and SSH key from your Ansible container that you used for the current DVWA machine.

- You may need to start your Ansible container on your jump box to get the key.

Run `sudo docker container list -a` to see a list of all the containers. You should only have one. Note the unique name of your container.

- Run the following commands to start your container and get the key:

  ```bash
  $ sudo docker start your_container_name
  your_container_name
  $ sudo docker attach your_container_name
  $ cat .ssh/id_rsa.pub 
  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdFS0nrcNG91P3HV60pPCDE0YCKNeS5Kr8edGxCeXUT1SP09Eyxxpi6LPZbL0Nkn8JNtdaxN9qyWG4Xpuh+rzCl9QnnGsdge76muzwl6awVUvRn0IAjM/e3RCKt0e1xSRiGaUY1ch41NY1Dih/MjxPunC2BykSGP17/hgMmLPKe8ZsHVaiFv1SiEqsGHa/
  ```

Point out that you need to copy the key into your configuration.

![](Images/new-VM/new-vm-config.png)

You will not give the new VM an external IP address, so it can only be accessed either by your jump box or the load balancer.

We could assign a load balancer right now, but we will leave this at the default setting. We will assign the load balancer in the next lesson. 

![](../2/Images/provisioner-setup/vm-networking.png)

Explain that you will verify your connection between your Ansible container and the new VM using SSH.

```bash
$ ssh sysadmin@10.0.0.7
The authenticity of host '10.0.0.7 (10.0.0.7)' can't be established.
ECDSA key fingerprint is SHA256:Jes0kNsSifAVf/TEcfPxhP4/p2fmS7WGk2O8xo8vC64.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.0.0.7' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 5.0.0-1027-azure x86_64)
```
- Run `exit` to return to your Ansible container.
- Add the internal IP address of the new VM to your Ansible configuration.
- Get the internal IP from the VM details page in Azure:
  ![](3/Images/new-VM/vm-details.png)
On your Ansible container, run `nano /etc/ansible/hosts`.
- Add the new IP address under the IP of your other VM.
  ```bash
  # Ex 2: A collection of hosts belonging to the 'webservers' group
  [webservers]
  ## alpha.example.org
  ## beta.example.org
  ## 192.168.1.100
  ## 192.168.1.110
  10.0.0.6
  10.0.0.7
  # If you have multiple hosts following a pattern you can specify
  # them like this:
  ```
  
  - Save and exit the hosts file.
Ask if any students have questions about editing the hosts file.
Explain that you will test your Ansible configuration with the Ansible `ping` command.
- Run `ansible all -m ping` (Ignore `[DEPRECATION WARNING]` if )
  ```bash
  root@1f08425a2967:~# ansible all -m ping
  10.0.0.6 | SUCCESS => {
      "changed": false, 
      "ping": "pong"
  }
  10.0.0.7 | SUCCESS => {
      "changed": false, 
      "ping": "pong"
  }
	10.0.0.8 | SUCCESS => {
		"changed": false, 
		"ping": "pong"
  }
  ```
Ask if anyone has any questions about this `ping` command.
Run your Ansible playbook to configure your new machine.
- **Hint**: If you run your playbook, it will run on both machines. Notice that Ansible will recognize your original VM and check its settings. It should only make changes to the new VM.
- Run `ansible-playbook your-playbook.yml`
  ```bash
  root@1f08425a2967:~# ansible-playbook /etc/ansible/pentest.yml 
  PLAY [Config Web VM with Docker] ****************************************************
  TASK [Gathering Facts] **************************************************************
  ok: [10.0.0.7]
  ok: [10.0.0.6]
  TASK [docker.io] ********************************************************************
  ok: [10.0.0.6]
  [WARNING]: Updating cache and auto-installing missing dependency: python-apt
  changed: [10.0.0.7]
  TASK [Install pip] ******************************************************************
  ok: [10.0.0.6]
  changed: [10.0.0.7]
  TASK [Install Docker python module] *************************************************
  ok: [10.0.0.6]
  changed: [10.0.0.7]
  TASK [download and launch a docker web container] ***********************************
  changed: [10.0.0.6]
  changed: [10.0.0.7]
  PLAY RECAP **************************************************************************
  10.0.0.6                   : ok=5    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
  10.0.0.7                   : ok=5    changed=4    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
  ```
Explain that once the Ansible playbook is finished running, you will SSH to the new VM and test the DVWA app using `curl`.
- Run `ssh [username]@[ip.of.vm]`
- Run `curl localhost/setup.php`
- Your output should look like the following:
  ```bash
  root@1f08425a2967:~# ssh sysadmin@10.0.0.7
  Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 5.0.0-1027-azure x86_64)
  * Documentation:  https://help.ubuntu.com
  * Management:     https://landscape.canonical.com
  * Support:        https://ubuntu.com/advantage
    System information as of Fri Jan 10 21:01:52 UTC 2020
    System load:  0.24              Processes:              122
    Usage of /:   9.9% of 28.90GB   Users logged in:        0
    Memory usage: 57%               IP address for eth0:    10.0.0.7
    Swap usage:   0%                IP address for docker0: 172.17.0.1
  19 packages can be updated.
  16 updates are security updates.
  Last login: Fri Jan 10 20:57:26 2020 from 10.0.0.4
  ansible@Pentest-2:~$ curl localhost/setup.php
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
  <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
      <title>Setup :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>
      <link rel="stylesheet" type="text/css" href="dvwa/css/main.css" />
      <link rel="icon" type="\image/ico" href="favicon.ico" />
      <script type="text/javascript" src="dvwa/js/dvwaPage.js"></script>
    </head>
  #Truncated
  ```
Ask if there are any questions about this activity.
Students should now have two VMs running DVWA behind a load balancer.
Ask if there are any questions about this setup before concluding class.
---
|:warning: **CHECKPOINT** :warning:|
|:-:|
| Use the [Daily Checklist](../Resources/Checklist.md) to verify that students are ready for the next class session. |
At the end of Day 3, students should have completed the following critical items.
- [ ] An Ansible playbook has been created that configures Docker and downloads a container.
- [ ] The Ansible playbook is able to be run on the Web VMs.
- [ ] The Web VMs are running a DVWA Docker container.
- [ ] A load balancer has been created and at least 2 Web VMs placed behind it.
- [ ] The DVWA site is able to be accessed through the load balancer from the internet.
Failure to complete these steps will hinder the activities in the next class.