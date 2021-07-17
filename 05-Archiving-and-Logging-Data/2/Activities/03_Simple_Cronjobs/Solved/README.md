## Solution Guide: Simple Cron Jobs

Completing this activity required the following steps:

- Using ` systemctl` to verify that the `cron` daemon is installed and running.
- Using ` crontab –l` to inspect user crontab and verify its validity.
- Using ` crontab -e` to edit user crontab files.
- Using ` crontab` to automate cron jobs to move and archive files and directories.
- Verifying archives after they are written to check for errors.

### Walkthrough

- Start by verifying that the `cron` service is running.

    - Run `systemctl status cron`

- Inspect your user crontab to ensure no one has tampered with it. 

- Observe that there are not uncommented lines present in the crontab.

    - Run  `crontab -l`

- Now that you're sure `cron` is up and running, you'll schedule some jobs to periodically clean up the `sysadmin` user's home folder. Specifically, these jobs will move files out of `~/Downloads` and sort them into the appropriate directory for their file types. In order to schedule them, you'll need to create the following directories:

  - `/usr/share/doctors`
  - `/usr/share/patients`
  - `/usr/share/treatments`

- Run the following command:

    `sudo mkdir -p /usr/share/doctors`  
    `sudo mkdir -p /usr/share/patients`  
    `sudo mkdir -p /usr/share/treatments`

   **Bonus**: Create all three directories with a single command. _(Hint: Use brace expansion.)_

   - Run: `sudo mkdir -p /usr/share/{doctors,patients,treatments}`

- Open your crontab for editing, and schedule the following jobs to run at the specified time intervals:

  - Every day at 6 p.m., move all `doctors*.docx` files in `~/Downloads` to `/usr/share/doctors`.
  - Every day at 6 p.m., move all `patients*.txt` files in `~/Downloads` to `/usr/share/patients`.
  - Every day at 6 p.m., move all `treatments*.pdf` files in `~/Downloads` to `/usr/share/treatments`.

- Run ` crontab -e`

- After opening the crontab file, scroll to the bottom and add the following lines:

    `0 18 * * * mv ~/Downloads/doctors*.docx /usr/share/doctors`

    - This command will schedule and move all `doctors*.docx` files in `~/Downloads` to `/usr/share/doctors` every day at 6 p.m..

    `0 18 * * * mv ~/Downloads/patients*.txt /usr/share/patients`

    - This command will schedule and move all `patients*.txt` files in `~/Downloads` to `/usr/share/patients`.

    `0 18 * * * mv ~/Downloads/treatments*.pdf /usr/share/treatments`
    
    - Make sure to close and save your crontab files before moving on.

- After scheduling your jobs, double-check that your crontab has been created in `/var/spool/cron`. Remember the path to your crontab file once you find it.

    - Run  `sudo ls -l /var/spool/cron/crontabs | grep sysadmin`


#### Bonus

Create the following additional cron jobs.

- Every Friday at 11 p.m., create a compressed tarball of all files in `~/research` in `~/Documents/MedicalArchive`. Name the archive `Medical_backup.tar.gz`.

    `0 23 * * 5 tar cvf ~/Documents/MedicalArchive/Medical_backup.tar.gz ~/research`

- Every Friday at 11:05 p.m., verify the validity of the archive `Medical_backup.tar.gz`.

    `5 23 * * 5 gzip -t Medical_backup.tar.gz >> /usr/share/backup_validation.txt`


- This command will perform a long listing of the `~/Downloads` directory daily at 4 a.m. It will then send the output to the `~/Documents/Medical_files_list.txt`.

    `0 4 * * * ls -l ~/Downloads > ~/Documents/Medical_files_list.txt`

- After scheduling your jobs, double-check that your crontab has been created in `/var/spool/cron`. Remember the path to your crontab file once you find it.

    `sudo ls -l /var/spool/cron/crontabs | grep sysadmin`


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
