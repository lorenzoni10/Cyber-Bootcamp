## Activity File: Simple Cron Jobs

In this activity, you are a junior administrator at *Rezifp Pharma Inc*. 

- In response to the ransomware attacks, you are responsible for using `cron` to automate backup jobs for the E-Prescription Treatment database. 

- The company maintains a large number of files associated with patients, doctors, and their treatments. Administrators at various clinics often create files that contain the `.txt` file extension—e.g., `patients12987.txt`, and store them in their user downloads folders.

- The  E-Prescription Treatment database data is used by several departments at *Rezifp Pharma Inc.* and contains Personal Identifiable Information (PII) such as email addresses, passwords, and biometric records. 

- Your work will ensure the integrity and availability of the data and help ensure compliance with HIPAA regulations required by all medical institutions that collect and store patient health information.

You have been tasked to:

- Create` /doctors`, `/patients`, and `/treatments` directories under `/usr/share`.

- Automate a cron job that organizes the files created by administrators by moving them from the users' `~/Downloads` directories into the `/usr/share/doctors, /usr/share/patients, and /usr/share/treatments` directories, where they can be read by all users.

- Automate daily _full backups_ of the directories and files in the `/usr/share` directory.

- Automate daily _full backups_ of the user's `~/Downloads` directory into the `/usr/share` directory.

- Verify the archive _after it is written_ to check for errors.

### Instructions

1. Start by verifying that the `cron` service is running.

2. Inspect your user crontab to ensure no one has tampered with it. 

3. Observe that there are no uncommented lines present in the crontab.

4. Now that you're sure `cron` is up and running, schedule some jobs to periodically clean up the `sysadmin` user's home folder. 

    - Specifically, these jobs will move files out of `~/Downloads` and sort them into the appropriate directory for their file type. To schedule them, create the following directories:

        - `/usr/share/doctors`
        - `/usr/share/patients`
        - `/usr/share/treatments`
 
    - **Bonus:** Create all three directories with a single command. (_Hint: Use brace expansion._)

5. Open your crontab for editing, and schedule the following jobs to run at the specified time intervals:
  - Every day at 6 p.m., move all `doctors*.docx` files in `~/Downloads` to `/usr/share/doctors`.
  - Every day at 6 p.m., move all `patients*.txt` files in `~/Downloads` to `/usr/share/patients`.
  - Every day at 6 p.m., move all `treatments*.pdf` files in `~/Downloads` to `/usr/share/treatments`.

    Close and save your crontab files before moving on.

7. Double-check that your crontab has been created in `/var/spool/cron`. Remember the path to your crontab file once you find it.

#### Bonus

Create the following cron jobs:

  - Every Friday at 11 p.m., create a compressed tarball of all files in `~/research` in `~/Documents/MedicalArchive`. Name the archive `Medical_backup.tar.gz`.

  - Every Friday at 11:05 p.m., verify the validity of the archive `Medical_backup.tar.gz`.
  
  - Every day at 4 a.m., create a list of all files in `~/Downloads`. Save it to `~/Documents/Medical_files_list.txt`.

    Close and save your crontab files before moving on.

- Double-check that your crontab has been created in `/var/spool/cron`. Remember the path to your crontab file once you find it.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
