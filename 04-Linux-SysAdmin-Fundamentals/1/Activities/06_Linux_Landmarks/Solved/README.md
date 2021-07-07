## Solution File: Linux Landmarks

### Setup

To set up this activity, you will need to run this command: `sudo bash /home/instructor/Documents/setup_scripts/instructor/landmarks_review.sh`
    
- Ignore any `rm: cannot remove` errors you find.

### Solutions

Log into the lab environment with the username `sysadmin` and password `cybersecurity`.

1. Create a `research` directory in your home folder.
     - Run `cd /home/sysadmin/`.
     - Run `mkdir research`.


2. Access the /var/log directory; check to see if the `auth.log` exists, as you need this to check for suspicious logins.
    - Run `ls /var/log/auth.log`
    - This will confirm the file exists.

3. Access your personal home directory; check to see if you have a `Desktop` and `Downloads` directory.

    - Run `ls /home/sysadmin/`.
    - The Desktop and Downloads directories will appear.

4. Access the binary directory; check to see if you can find `cat` and `ps` binary files.
    
    - Run `ls /bin/cat`.
    - Run `ls /bin/ps`.
    - This will confirm the files exist.

5. Check to see if there are any scripts in temporary directories, as those may be suspicious.
    - Run `ls /tmp`.
    - This directory contains a shell script called `str.sh`. This file is out of place, and should be noted for later analysis.

6. Check that the only users with accounts in the `/home` directory are `adam`, `billy`, `instructor`, `jane`, `john` `max`, `sally`, `student`, `sysadmin` and `vagrant`. There should not be additional directories. Note any other users that you see.
    
    - Run `ls /home`. 
    - This revealed home folders named `jack` and `http`.


-------

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.



