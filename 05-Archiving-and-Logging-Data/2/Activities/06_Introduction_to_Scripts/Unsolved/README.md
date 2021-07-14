## Activity File: Introduction to Scripting

In this activity, you are a junior administrator at Rezifp Pharma Inc. 

- It is your responsibility to ensure the security of the organization’s network by automating many tasks, such as moving patient data files, from various locations using `cron`. 

- Many of these tasks are accomplished through automation, using scripts written to run at regular intervals or as periodically as determined by your department. 

- In response to malware, adware, and virus attacks, your organization has asked you to ensure proper configuration management of all networking equipment and associated systems. 

- In addition to the threat of malware and attacks, portions of the Health and Portability Act (HIPAA), require organizations to maintain a regular backup regimen for the safe and secure storage of patient data. In response to HIPAA regulations, your organization also ensures that any unused, temporary, and cached files are removed regularly.

You have been tasked to:

- Create a script, `backup.sh`, that creates a backup of the system's `/home` directory.

- Create a script, `update.sh`, that upgrades packages to their most recent version, keeping the system up-to-date.

- **Bonus:** Create a script, `cleanup.sh`, that removes any unused, temporary, and cached files.

- Test the scripts by running them with bash, using the `sudo ./<name of the script>.sh` command.

### Instructions

1. Begin by creating a directory to hold your scripts in `~/Security_scripts`. Then, move into this directory.

2. Create a script file called `backup.sh` that does the following:

    - Creates a tar archive of `/home`. Save this to `/var/backup/home.tar`.
    
    - Moves the file `/var/backup/home.tar` to `/var/backup/home.MMDDYYYY.tar`. This allows you to save both the last backup you made, and the one you'll make now. **Note:** You can use any date you want, as long as it is in the `MMDDYYYY` format. 

    - Lists all files in `/var/backup`, including file sizes, and saves the output to `/var/backup/file_report.txt`. `ls -lh` or `ls -lah`  is useful for this task.

    - Prints how much memory your machine has free. Save this to a file called `/var/backup/disk_report.txt`. `free -h` is useful for this task.

     **Hint**: 

     - `free -h` prints free memory. 
     - `ls -lh` produces a long listing, including human-readable file sizes.

3. Create a script file called `update.sh` that does the following:

    - Updates `apt`.

    - Runs a command to upgrade all installed packages.

    - Runs a command to install new packages and upgrade the system.

    - Runs a command to remove unnecessary packages and their associated configurations.

    - **Bonus:** Add a line to the bottom of `update.sh` combining all of the commands with a single line of code.

4. Make all scripts executable.

5. Test the scripts by running them with bash using the `sudo ./<name of the script>.sh` command.

   - **Note:** When testing `backup.sh`, stop the script with `Ctrl + C`. Otherwise, it will take a long time to create a full backup of `/home`. We just want to confirm that it successfully runs. 

#### Bonus

6. Create a file called `cleanup.sh` that does the following:
 
    - Removes all files in `/tmp` and `/var/tmp`.

    - Clears the `apt` cache.

    - Cleans the `thumbnails` cache.

7. Research online and define the following terms: "apt cache" and "thumbnails cache."


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
