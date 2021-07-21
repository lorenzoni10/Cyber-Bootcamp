## Solution File: Log Size Management

The goal of this activity was to learn how to edit the logrotate configuration file and establish a log rotation scheme based on a specific set of criteria. Since system logging daemons do not allow us to control log file sizes, we use a tool like Logrotate to fill this gap.

### Solutions

In your Ubuntu VM, launch a terminal and run the following commands:

1. Verify you have the most up-to-date version of logrotate installed. 

    - Run `sudo apt install logrotate`

      ```bash
      [sudo] password for sysadmin:
      Reading package lists... Done
      Building dependency tree
      Reading state information... Done
      logrotate is already the newest version (3.11.0-0.1ubuntu).
      ...
      ...
      ```
      
- **Note:** Your version may slightly differ. 


3. To configure the default parameters for logrotate, edit `/etc/logrotate.conf` as follows:

   - Run `sudo nano /etc/logrotate.conf` and add the following update: 

        -	Implement a rotation scheme to keep four weeks of backlogs.

            ```bash
            # Keep 4 weeks of backlogs
            rotate 4
            ```

        -	Create new empty log file after rotating old ones.

            ```bash
            # Create new (empty) log file after rotating old ones
            create
            ```

        -	Do not rotate empty logs.

            ```bash
            # Do not rotate empty logs
            notifempty
            ```

        -	Compress log files.

            ```bash
            # Compress log files
            compress
            ```

2.	List the contents of `logrotate.d` to see what configuration files are present.
    
     - Run  `ls -lat /etc/logrotate.d`

        ```bash
        total 76
        drwxr-xr-x 142 root root 12288 Apr 30 04:38 ..
        drwxr-xr-x   2 root root  4096 Apr 29 10:47 .
        -rw-r--r--   1 root root   442 Jul 16  2019 apache2
        -rw-r--r--   1 root root   235 Apr 29  2019 unattended-upgrades
        -rw-r--r--   1 root root   819 Mar 29  2019 samba
        -rw-r--r--   1 root root   173 Apr 20  2018 apt
        -rw-r--r--   1 root root   329 Apr  6  2018 nginx
        -rw-r--r--   1 root root   181 Mar 27  2018 cups-daemon
        -rw-r--r--   1 root root    94 Feb 26  2018 ppp
        -rw-r--r--   1 root root    79 Jan 16  2018 aptitude
        -rw-r--r--   1 root root   501 Jan 14  2018 rsyslog
        -rw-r--r--   1 root root   533 Dec 15  2017 speech-dispatcher
        -rw-r--r--   1 root root   126 Nov 20  2017 apport
        -rw-r--r--   1 root root   120 Nov  2  2017 alternatives
        -rw-r--r--   1 root root   112 Nov  2  2017 dpkg
        -rw-r--r--   1 root root   178 Aug 15  2017 ufw
        -rw-r--r--   1 root root   126 May  7  2014 vsftpd

4. While still in `/etc/logrotate.d`, create files for the following logs and add the following criteria. 

     `/var/log/auth.log` parameters: `180 days of backlog`, `rotate daily`, `Don't rotate empty logs`, `Compress the file`, `Delay the compression`.

    - Run `nano auth` to create a new file. 
    
    - Add the following contents: 

        ```bash
        /var/log/auth.log {
            rotate 180
            daily
            notifempty
            compress
            delaycompress
            endscript
        }
        ```
     - Save and exit the file. 
    
    `/var/log/cron.log` parameters: `60 days of backlog`, `rotate daily`, `Don't rotate empty logs`, `Compress the file`, `Delay the compression`.
    
     - Run `nano cron` to create a new file. 
    
     - Add the following contents: 


        ```bash
        /var/log/cron.log {
            rotate 60
            daily
            notifempty
            compress
            delaycompress
            endscript
        }
        ```
     - Save and exit the file. 

    `/var/log/boot.log` parameters: `30 days of backlog`, `rotate daily`, `Don't rotate empty logs`, `Compress the file`, `Delay the compression`.

     - Run `nano boot` to create a new file. 
    
     - Add the following contents: 

        ```bash
        /var/log/boot.log {
            rotate 30
            daily
            notifempty
            compress
            delaycompress
            endscript
        }
        ```
     - Save and exit the file. 

#### Bonus

5. Test the rotation by forcing Logrotate to rotate the logs by verifying the dates.

   - Run `sudo logrotate -vf /etc/logrotate.conf`. If you see `old log` in the output, run the command again until you see `rotating pattern` in the output.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
