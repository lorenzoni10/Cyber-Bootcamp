## Solution Guide: Provisioners

In this activity, you launched a new VM from the Azure portal that could only be accessed using a new SSH key from the container running inside your jump box.

---

1. Connect to your Ansible container. Once you're connected, create a new SSH key and copy the public key.

    - Run `sudo docker container list -a` to find your image.

    - Run `docker run -it cyberxsecurity/ansible /bin/bash` to start your container and connect to it. (Note that the prompt changes.)

        ```bash
        root@Red-Team-Web-VM-1:/home/RedAdmin# docker run -it cyberxsecurity/ansible /bin/bash
        root@23b86e1d62ad:~#
        ```

    - Run `ssh-keygen` to create an SSH key.

        ```bash
        root@23b86e1d62ad:~# ssh-keygen
        Generating public/private rsa key pair.
        Enter file in which to save the key (/root/.ssh/id_rsa):
        Created directory '/root/.ssh'.
        Enter passphrase (empty for no passphrase):
        Enter same passphrase again:
        Your identification has been saved in /root/.ssh/id_rsa.
        Your public key has been saved in /root/.ssh/id_rsa.pub.
        The key fingerprint is:
        SHA256:gzoKliTqbxvTFhrNU7ZwUHEx7xAA7MBPS2Wq3HdJ6rw root@23b86e1d62ad
        The key's randomart image is:
        +---[RSA 2048]----+
        |  . .o+*o=.      |
        |   o ++ . +      |
        |    *o.+ o .     |
        |  . =+=.+ +      |
        |.. + *.+So .     |
        |+ . +.* ..       |
        |oo +oo o         |
        |o. o+.  .        |
        | .+o.  E         |
        +----[SHA256]-----+
        root@23b86e1d62ad:~#
        ```

    - Run `ls .ssh/` to view your keys.

        ```bash
        root@23b86e1d62ad:~# ls .ssh/
        id_rsa  id_rsa.pub
        ```

    - Run `cat .ssh/id_rsa.pub` to display your public key.

        ```bash
        root@23b86e1d62ad:~# cat .ssh/id_rsa.pub
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDz5KX3urPPKbYRKS3J06wyw5Xj4eZRQTcg6u2LpnSsXwPWYBpCdF5lE3tJlbp7AsnXlXpq2G0oAy5dcLJX2anpfaEBTEvZ0mFBS24AdNnF3ptan5SmEM/
        ```

    - Copy your public key string.

2. Return to the Azure portal and locate one of your web-vm's details page.

		- Reset your Vm's password and use your container's new public key for the SSH user.

    - Get the internal IP for your new VM from the Details page.

![](../../../Images/web-reset-ssh/reset-ssh.png)

3. After your VM launches, test your connection using `ssh` from your jump box Ansible container.
    - Note: If only TCP connections are enabled for SSH in your security group rule, ICMP packets will not be allowed, so you will not be able to use `ping`.

    ```bash
    root@23b86e1d62ad:~# ping 10.0.0.6
    PING 10.0.0.6 (10.0.0.6) 56(84) bytes of data.
    ^C
    --- 10.0.0.6 ping statistics ---
    4 packets transmitted, 0 received, 100% packet loss, time 3062ms

    root@23b86e1d62ad:~#
    ```

    ```bash
    root@23b86e1d62ad:~# ssh ansible@10.0.0.6
    The authenticity of host '10.0.0.6 (10.0.0.6)' can't be established.
    ECDSA key fingerprint is SHA256:7Wd1cStyhq5HihBf+7TQgjIQe2uHP6arx2qZ1YrPAP4.
    Are you sure you want to continue connecting (yes/no)? yes
    Warning: Permanently added '10.0.0.6' (ECDSA) to the list of known hosts.
    Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 5.0.0-1027-azure x86_64)

    * Documentation:  https://help.ubuntu.com
    * Management:     https://landscape.canonical.com
    * Support:        https://ubuntu.com/advantage

    System information as of Mon Jan  6 18:49:56 UTC 2020

    System load:  0.01              Processes:           108
    Usage of /:   4.1% of 28.90GB   Users logged in:     0
    Memory usage: 36%               IP address for eth0: 10.0.0.6
    Swap usage:   0%


    0 packages can be updated.
    0 updates are security updates.


    Last login: Mon Jan  6 18:33:30 2020 from 10.0.0.4
    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.

    ansible@Pentest-1:~$
    ```

    - Exit this SSH session by running `exit`.

4. Locate the Ansible config file and hosts file.

    ```bash
    root@1f08425a2967:~# ls /etc/ansible/
    ansible.cfg  hosts  roles
    ```
     - Add this machine's internal IP address to the Ansible hosts file.

    - Open the file with `nano /etc/ansible/hosts`.
    - Uncomment the `[webservers]` header line.
    - Add the internal IP address under the `[webservers]` header.
		- Add the python line: `ansible_python_interpreter=/usr/bin/python3` besides each IP.

    ```bash
        # This is the default ansible 'hosts' file.
        #
        # It should live in /etc/ansible/hosts
        #
        #   - Comments begin with the '#' character
        #   - Blank lines are ignored
        #   - Groups of hosts are delimited by [header] elements
        #   - You can enter hostnames or ip addresses
        #   - A hostname/ip can be a member of multiple groups
        # Ex 1: Ungrouped hosts, specify before any group headers.

        ## green.example.com
        ## blue.example.com
        ## 192.168.100.1
        ## 192.168.100.10

        # Ex 2: A collection of hosts belonging to the 'webservers' group

        [webservers]
        ## alpha.example.org
        ## beta.example.org
        ## 192.168.1.100
        ## 192.168.1.110
        10.0.0.6 ansible_python_interpreter=/usr/bin/python3
				10.0.0.7 ansible_python_interpreter=/usr/bin/python3
        ```

5. Change the Ansible configuration file to use your administrator account for SSH connections.

    - Open the file with `nano /etc/ansible/ansible.cfg` and scroll down to the `remote_user` option.

    - Uncomment the `remote_user` line and replace `root` with your admin username using this format:
				- `remote_user = <user-name-for-web-VMs>`

	Example:
    ```bash
    # What flags to pass to sudo
    # WARNING: leaving out the defaults might create unexpected behaviours
    #sudo_flags = -H -S -n

    # SSH timeout
    #timeout = 10

    # default user to use for playbooks if user is not specified
    # (/usr/bin/ansible will use current user as default)
    remote_user = sysadmin

    # logging is off by default unless this path is defined
    # if so defined, consider logrotate
    #log_path = /var/log/ansible.log

    # default module name for /usr/bin/ansible
    #module_name = command

    ```

6. Test an Ansible connection using the appropriate Ansible command.

If you used `ansible_python_interpreter=/usr/bin/python3` your output should look like:

```bash
10.0.0.5 | SUCCESS => {
"changed": false, 
"ping": "pong"
}
10.0.0.6 | SUCCESS => {
		"changed": false, 
		"ping": "pong"
}
```

If that line isn't present, you will get a warning like this:

```bash
root@1f08425a2967:~# ansible all -m ping
[DEPRECATION WARNING]: Distribution Ubuntu 18.04 on host 10.0.0.6 should use 
/usr/bin/python3, but is using /usr/bin/python for backward compatibility with 
prior Ansible releases. A future Ansible release will default to using the 
discovered platform python for this host. See https://docs.ansible.com/ansible/
2.9/reference_appendices/interpreter_discovery.html for more information. This 
feature will be removed in version 2.12. Deprecation warnings can be disabled 
by setting deprecation_warnings=False in ansible.cfg.
10.0.0.6 | SUCCESS => {
		"ansible_facts": {
				"discovered_interpreter_python": "/usr/bin/python"
		}, 
		"changed": false, 
		"ping": "pong"
}
```

- Ignore the `[DEPRECATION WARNING]` or add the line `ansible_python_interpreter=/usr/bin/python3` next to each Ip address in the hosts file.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 