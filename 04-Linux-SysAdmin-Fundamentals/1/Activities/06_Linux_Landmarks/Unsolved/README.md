## Activity File: Linux Landmarks

For the activities over the next few days, you will act as a **Junior Linux Systems Administrator** at _Corp X_. A senior administrator has asked you to audit a malfunctioning Linux server. As such, all of the activities over the next week will take place in the same lab environment.

- You will complete several tasks in the next week of class activities and homeworks related to **Linux auditing and hardening**. Everything you do will be second nature for many Linux administrators, and are great skills to talk about during job interviews.

- The first step for troubleshooting any computer issue is gathering information. In this activity, the senior administrator has sent you a list of information to gather about the target system. You will use this information for further analysis.

- You will start with a basic audit of system files, exploring some of the most important locations in the file system to identify evidence of suspicious activity.

Use the following credentials to log into the lab environment:

- **Username**: `sysadmin`
- **Password**: `cybersecurity`

Be sure to ask your instructors and classmates for help if you get stuck.

### Instructions:

To set up this activity, run the following command: `sudo bash /home/instructor/Documents/setup_scripts/instructor/landmarks_review.sh`
    
- Ignore any `rm: cannot remove` errors that appear.

Here is the audit checklist provided by your senior administrator:

1. Create a `research` directory in your home folder to place notes of your findings.

2. Access the /var/log directory and check that the `auth.log` exists. You need this to check for suspicious logins.

3. Access your personal home directory and check if you have a `Desktop` and `Downloads` directory.

4. Access the binary directory and check if you can find `cat` and `ps` binary files.

5. Check if there are any scripts in temporary directories, as those may be suspicious.

6. Check that the only users with accounts in the `/home` directory are `adam`, `billy`, `instructor`, `jane`, `john` `max`, `sally`, `student`, `sysadmin` and `vagrant`. There should not be additional directories. Note any other users that you find.

-------

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

