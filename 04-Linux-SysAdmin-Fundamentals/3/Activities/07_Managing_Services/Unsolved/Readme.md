## Activity File: Managing Services

In this activity, you will continue with an audit of the services running on the server.

Your senior administrator wants you to audit the services and shut down insecure and/or unused services. They have provided a list of services to check.

You will check for these services and shut down and remove any that you find running on the server.

### Instructions

Your senior administrator provided the following notes:

- Note: Only the first three services are required, and the last two are offered as a bonus.

- Some of our systems may have old services running that are no longer used. Because services can be exploited, we want to run as few of them as possible. The services we should check for are:

  - **File Transfer Protocol (FTP)**: This file sharing service is outdated, insecure, and easily exploitable. Cybercriminals often use it to upload malicious files, so we need it removed immediately.

  - **Telnet**: We used to use Telnet to get a shell on this server from a remote computer. This allowed us to easily reconfigure the server while not being in the office. Unfortunately, Telnet is notoriously insecure and easily hacked. Remove it so no one can log in to this machine remotely.

  - **HTTP**: HTTP is used to send files over the Internet and host websites. This server is _not_ supposed to be hosting websites, so stop and remove this service.

  **BONUS**

    - **IMAP and/or POP3**: These services are used to send and receive email. This server should _not_ be managing emails, so stop and remove these services.

    - **Network Information Service**: This is an old service that provides information about the entire network. Attackers often use this to gather information about this server and other machines on the network, which they can use to break in more easily. Stop and remove this service to prevent attackers from doing so.

- To check for the above services, make sure none of these is running:

   - vsftpd.service (FTP)
 
   - apache2.service (HTTP)

   - nginx.service (HTTP)

- **Bonus Services:**

  - xinetd.service (Telnet)

  - dovecot.service (IMAP or POP3)


- Complete the following for any of the listed services you find on the system:

    1. Stop the service.

    2. Verify that the service is stopped.

    3. Disable the service. (:warning: Do not disable `apache2` or `nginx`. They will be needed for a later activity)

    4. Remove the service from the system. (Note: Take note of the commands to remove these services, but do not actually remove them. We will use them again for the next activity.)

        _**Hint**: Dovecot comes in two packages: `dovecot-imapd` and `dovecot-pop3d`. You'll need to remove both to successfully uninstall this service._


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

