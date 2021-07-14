## Student Activity: Log Filtering
 
In this activity, you are a junior administrator at Rezifp Pharma Inc. The company maintains a large database of files associated with patients, doctors, and treatments. These files are maintained on a local server.
 
- You will conduct a brief training session for a new staff member demonstrating how to use `journalctl` to investigate journal messages for suspicious activity.
 
- You will put on your black hat and assume the role of a criminal hacker who has successfully breached a user account with admin privileges.
 
- Thinking like a hacker, you will attempt to establish persistence by creating a fake user account and then add them to the **sudoers** file, thus providing the criminal hacker with admin privileges.
 
#### Notes

- Using manpages or Google may come in assistance for this activity. 

- You may need to use the `sudo` command.

### Instructions
  
1. Ensure that logs are saved across reboots by checking if `journalctl` is running in persistent mode. 

   - Checking the `/etc/systemd/journald.conf` for `Storage`:
 
     - Run `grep Storage /etc/systemd/journald.conf`
 
       Output should appear as below:
    
        ```bash
        #Storage=auto
        ```
    - If not then modify these settings in `/etc/systemd/journald.conf`.
 
     - Run: `sudo nano /etc/systemd/journald.conf`
 
       ```bash
       #  This file is part of systemd.
       #
       #  systemd is free software; you can redistribute it and/or modify it
       #  under the terms of the GNU Lesser General Public License as published by
       #  the Free Software Foundation; either version 2.1 of the License, or
       #  (at your option) any later version.
       #
       # Entries in this file show the compile time defaults.
       # You can change settings by editing this file.
       # Defaults can be restored by simply deleting this file.
       #
       # See journald.conf(5) for details.
 
       [Journal]
       #Storage=auto
       #Compress=yes
       ```
 
     - `Storage=` is the persistence setting and `auto` indicates logging persistence if space is available.
 
       - Uncomment the `Storage=auto` and save the file.
 
    - Whenever the `journal.conf` file is modified, `systemd-journald` needs to be restarted before the changes take effect.
 
      - Run: `sudo systemctl restart systemd-journald`
 
      - Log persistence is now enabled.
 
2. Now we'll assume the role of an attacker who breached a user's account with admin privileges and is now trying to create a fake account to establish login persistence.
 
    - For this part of the activity, you will need to open two terminals side by side.
 
      - **Terminal #1** will be your real-time journal messages window.
      - **Terminal #2** will be where you perform your attacks.
 
   **Terminal #1**
 
     - Run `journalctl -ef`
 
   **Terminal #2**
 
    - Create a fake user account.
 
      - Run: `sudo adduser hacker`
      - Password is `hack`
      - Leave all other settings as default by tapping the `Enter` key several times until done.
 
    - Thinking like a criminal hacker, let's perform privileges escalation by adding this newly created user to the **sudoers** file. This will provide the hacker account with admin privileges.
 
      - Type: `sudo usermod -aG sudo hacker`
 
   **Terminal #1**
 
    - View the results of the journal messages and find the malicious activity performed by the criminal hacker.
 
    - Your output should look similar to the following:
 
     ```
     Jul 15 17:59:18 cyber-security-ubuntu sudo[12974]: instructor : TTY=pts/1 ; PWD=/home/instructor ; USER=root ; COMMAND=/usr/sbin/adduser criminalhacker
     Jul 15 17:59:18 cyber-security-ubuntu sudo[12974]: pam_unix(sudo:session): session opened for user root by (uid=0)
     Jul 15 17:59:18 cyber-security-ubuntu groupadd[12976]: group added to /etc/group: name=criminalhacker, GID=1017
     Jul 15 17:59:18 cyber-security-ubuntu groupadd[12976]: group added to /etc/gshadow: name=criminalhacker
     Jul 15 17:59:18 cyber-security-ubuntu groupadd[12976]: new group: name=criminalhacker, GID=1017
     Jul 15 17:59:18 cyber-security-ubuntu useradd[12980]: new user: name=criminalhacker, UID=1013, GID=1017, home=/home/criminalhacker, shell=/bin/bash
     Jul 15 17:59:31 cyber-security-ubuntu passwd[12988]: pam_unix(passwd:chauthtok): password changed for criminalhacker
     Jul 15 17:59:31 cyber-security-ubuntu passwd[12988]: gkr-pam: couldn't update the login keyring password: no old password was entered
     Jul 15 17:59:33 cyber-security-ubuntu chfn[12989]: changed user 'criminalhacker' information
     Jul 15 17:59:33 cyber-security-ubuntu sudo[12974]: pam_unix(sudo:session): session closed for user root
     Jul 15 18:00:01 cyber-security-ubuntu CRON[12996]: pam_unix(cron:session): session opened for user smmsp by (uid=0)
     Jul 15 18:00:01 cyber-security-ubuntu CRON[12997]: (smmsp) CMD (test -x /etc/init.d/sendmail && test -x /usr/share/sendmail/sendmail && test -x /usr/lib/sm.bin/sendmail && /usr/share/sendmail/sendmail cron-msp)
 
     Jul 15 18:00:25 cyber-security-ubuntu sudo[13020]: instructor : TTY=pts/1 ; PWD=/home/instructor ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo criminalhacker
     Jul 15 18:00:25 cyber-security-ubuntu sudo[13020]: pam_unix(sudo:session): session opened for user root by (uid=0)
     Jul 15 18:00:25 cyber-security-ubuntu usermod[13021]: add 'criminalhacker' to group 'sudo'
     Jul 15 18:00:25 cyber-security-ubuntu usermod[13021]: add 'criminalhacker' to shadow group 'sudo'
     Jul 15 18:00:25 cyber-security-ubuntu sudo[13020]: pam_unix(sudo:session): session closed for user root
     ```
 
 - Answer the following questions. What does the journal message reveal about this malicious activity?
 
   - Was the hacker able to successfully create a fake user account?
 
   - What user account was breached in this scenario?
 
   - What is the `UID` and `GUID` of the fake account?
  
   - Was the criminal hacker able to successfully create a sendmail account?
 
   - Did the criminal hacker provide admin privileges to the fake user's account?
  
   - Was the attacker able to successfully establish persistence?
 
#### Bonus: Ghost in the Machine
 
3. Criminal hackers operate under an umbrella of stealth and perform malicious activities under other identities. For the bonus, you have been tasked with identifying the source of malicious activity using `journalctl`.
 
   **Terminal #1**

     - Run `journalctl -ef`.
 
   **Terminal #2**
 
     - Create a new user account as follows:
 
       - `sudo adduser badguy`
 
       - Password is `steal`
 
       - Leave all other settings as default by tapping the `enter` key several times until done.
 
     - Now let's use journalctl to check activity under the criminal hacker's user ID.
 
       - Logged in as criminal hacker, check your UID:
 
       - Run: `id`
 
       - Take note of the user ID. For this example, we'll use `1013`.
 
       - Run: `journalctl _UID=1013`
 
    - What did the `journalctl -ef` output display the malicious activity performed by the attacker and `journalctl _UID=1013` did not?
 
 
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
