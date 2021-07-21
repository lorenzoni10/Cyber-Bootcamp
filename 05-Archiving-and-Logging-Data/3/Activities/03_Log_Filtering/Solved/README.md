## Solution File: Log Filtering
 
The goal of this activity was to use `journalctl` to filter log files. Massive amounts of information exist within Linux logs, and the challenge is in knowing how to extract it.
 
### Solution

1. Check if `journalctl` is running in persistent mode to ensure that logs are saved across reboots.
 
   - This is accomplished by checking the `/etc/systemd/journald.conf` for `Storage`.
 
   - Run `grep Storage /etc/systemd/journald.conf`
 
    - Output should appear as below:
 
      ```bash
      #Storage=auto
      ```

   - If not, then modify these settings in `/etc/systemd/journald.conf`.
 
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
   - Uncomment the `Storage=auto` and save the file.
 
   - Whenever the `journal.conf` file is modified, `systemd-journald` needs to be restarted before the changes take effect.
 
     - Run: `sudo systemctl restart systemd-journald`
 
   - Log persistence is now enabled.
 
2. Now, we'll assume the role of an attacker who breached a user's account with admin privileges and is now trying to create a fake account to establish login persistence.
 
   - For this part of the activity, you will need to open two terminals side by side.
 
     - **Terminal #1** will be your real-time journal messages window.
     - **Terminal #2** will be where you perform your attacks.
 
  - **Terminal #1**
 
     - Run: `journalctl -ef`
 
  - **Terminal #2**
 
     - Create a fake user account:
 
       - Run: `sudo adduser hacker`
       - Password is `hack`
       - Leave all other settings as default by tapping the `enter` key several times until done.
 
     - Think like a criminal hacker here. Let's perform privilege escalation by adding this newly created user to the `sudoers` file. This will provide the hacker account with admin privileges.
 
      - Run: `sudo usermod -aG sudo hacker`
 
  - **Terminal #1**
 
     - View the results of the journal messages and find the malicious activity performed by the criminal hacker.
 
     - Your output should look similar to the following:
    
        ```
        Jul 15 17:59:18 cyber-security-ubuntu sudo[12974]: sysadmin : TTY=pts/1 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/sbin/adduser hacker
        Jul 15 17:59:18 cyber-security-ubuntu sudo[12974]: pam_unix(sudo:session): session opened for user root by (uid=0)
        Jul 15 17:59:18 cyber-security-ubuntu groupadd[12976]: group added to /etc/group: name=hacker, GID=1017
        Jul 15 17:59:18 cyber-security-ubuntu groupadd[12976]: group added to /etc/gshadow: name=hacker
        Jul 15 17:59:18 cyber-security-ubuntu groupadd[12976]: new group: name=hacker, GID=1017
        Jul 15 17:59:18 cyber-security-ubuntu useradd[12980]: new user: name=hacker, UID=1013, GID=1017, home=/home/hacker, shell=/bin/bash
        Jul 15 17:59:31 cyber-security-ubuntu passwd[12988]: pam_unix(passwd:chauthtok): password changed for hacker
        Jul 15 17:59:31 cyber-security-ubuntu passwd[12988]: gkr-pam: couldn't update the login keyring password: no old password was entered
        Jul 15 17:59:33 cyber-security-ubuntu chfn[12989]: changed user 'hacker' information
        Jul 15 17:59:33 cyber-security-ubuntu sudo[12974]: pam_unix(sudo:session): session closed for user root
        Jul 15 18:00:01 cyber-security-ubuntu CRON[12996]: pam_unix(cron:session): session opened for user smmsp by (uid=0)
    
        Jul 15 18:00:25 cyber-security-ubuntu sudo[13020]: sysadmin : TTY=pts/1 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo hacker
        Jul 15 18:00:25 cyber-security-ubuntu sudo[13020]: pam_unix(sudo:session): session opened for user root by (uid=0)
        Jul 15 18:00:25 cyber-security-ubuntu usermod[13021]: add 'hacker' to group 'sudo'
        Jul 15 18:00:25 cyber-security-ubuntu usermod[13021]: add 'hacker' to shadow group 'sudo'
        Jul 15 18:00:25 cyber-security-ubuntu sudo[13020]: pam_unix(sudo:session): session closed for user root
        ```
 
 - Document your findings. What does the journal message reveal about this malicious activity?
 
   - The attacker has successfully created a fake user account called **hacker**
 
   - The breached user account that was used to create the fake account was **sysadmin**.
 
   - The newly created fake account has a `UID=1013` and `GUID=1017`.
 
   - The criminal hacker has also successfully added the fake account to the **sudoers** files, providing them with admin privileges.
 
#### Bonus: `Ghost in the Machine`
 
3. Criminal hackers operate under an umbrella of stealth and perform malicious activities under other identities. In this bonus, you have been tasked with identifying the source of malicious activity using journalctl.
 
   - **Terminal #1**

     - Run `journalctl -ef`. 
 
   **Terminal #2**
 
     - Create a new user account:
 
       - `sudo adduser badguy`
    
       - Password is `steal`.
    
       - Leave all other settings as default by tapping the `enter` key several times until done.
 
     - Use `journalctl` to check activity under the criminal hacker's user ID.
 
       - Logged in as criminal hacker, check your UID: 
        
          - Run`id`
 
       - Take note of the user ID. For this example, we'll use `1013`.
 
       - Next, type: `journalctl _UID=1013`
 
     - What did the `journalctl -ef` output display when the malicious activity was performed that the `journalctl _UID=1013` did not?
 
       - **Answer**: The attacker used the `sudo` command to perform activity under the root account, which has a user ID of `0` therefore all activity will show under ID `0` instead of ID `1013`.
  
     - In the screenshot excerpt, we can see that the `journalctl -ef` window proves this theory.
 
        ```
        Jul 15 18:53:07 cyber-security-ubuntu sudo[14149]: pam_unix(sudo:session): session opened for user root by (uid=0)
        Jul 15 18:53:07 cyber-security-ubuntu groupadd[14151]: group added to /etc/group: name=badguy, GID=1015
        Jul 15 18:53:07 cyber-security-ubuntu groupadd[14151]: group added to /etc/gshadow: name=badguy
        ```
        -  **Note**: `session opened for user root by (uid=0)`
 
   This highlights the benefit of using `journalctl -ef` over `journalctl _UID=1013`.
 
---
 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
