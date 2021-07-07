## Solution Guide: Managing Services

 This activity was an audit of the services running on this server. To complete this activity, you needed to:

- Identify the services in the list that are installed and running on the machine.


- Stop each service.

- Disable each service.

- Uninstall each service.

Run `systemctl -t service --all` to determine which services are running.  The following services from the list are listed as present on the server:

- vsftpd.service (FTP)

- apache2.service (HTTP)

- nginx.service (HTTP)

**Bonus**

- xinetd.service (Telnet)

- dovecot.service (IMAP or POP3)

These services can help attackers gain access to the server, and none of them are necessary for the server to function properly.

- To stop a service:

  - Run `sudo systemctl stop <service_name>`

- To verify the service is stopped:

  - Run `systemctl status <service_name>`

  -Note: You can run systemctl against multiple services like this: `systemctl status <service_name_1> <service_name_2>`.  You can start, stop, enable, and disable multiple services at once too. 

- To disable the service:

  - Run `sudo systemctl disable <service_name>` 

    **Note:** Do not actually disable `nginx` or `apache2` from the system because they are needed later.

- To remove the service from the system:

  - Run `sudo apt remove <service_name>`

    **Note:** Do not actually remove `nginx` or `apache2` from the system because they are needed later.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  

