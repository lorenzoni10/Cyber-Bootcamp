## Activity File: Log Size Management

In this activity, you are a junior administrator at Rezifp Pharma Inc. The company maintains a large database of patient data associated with patients, doctors, and their treatments. These files are maintained on a local server.

The primary benefits of log rotation are preserving log entries and keeping log file sizes manageable. When a log file is rotated, the preserved log file can be compressed to save space.

You will create a log rotation scheme that keeps four weeks' worth of logs with a daily rotation that includes a maximum file size of 1 GB.

### Instructions


In your Ubuntu VM, launch a terminal. 

1. Verify you have the most up-to-date version of logrotate installed. 

2. Configure the following default parameters for logrotate by editing `/etc/logrotate.conf`: 

   - A rotation scheme keeping four weeks of backlogs.

   - Create new empty log files after rotating old ones.

   - Do not rotate empty logs.

   - Compress log files.

4. List the contents of `logrotate.d` to see what configuration files are present.

4. In `/etc/logrotate.d`, add configurations for the following directories:

    - For the log rotation rules for `/var/log/auth.log`, use the following parameters: `180 days of backlog`, `rotate daily`, `Don't rotate empty logs`, `Compress the file`, `Delay the compression`. Name the configuration file `auth`.

    - For the log rotation rules for  `/var/log/cron.log`, use the following parameters: `60 days of backlog`, `rotate daily`, `Don't rotate empty logs`, `Compress the file`, `Delay the compression`. Name the configuration file `cron`.

    - For the log rotation rules for  `/var/log/boot.log`, use the following parameters: `30 days of backlog`, `rotate daily`, `Don't rotate empty logs`, `Compress the file`, `Delay the compression`. Name the configuration file `boot`.


#### Bonus

5. Test the rotation by forcing logrotate to rotate the logs by verifying the dates.

    - Make sure that the proper lines are un-commented in the `etc/lograte.conf` file. 

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
