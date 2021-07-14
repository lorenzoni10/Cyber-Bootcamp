## Activity File: Restoring Data with Incremental Backups

In this activity, you will continue as a junior administrator at _Rezifp Pharma Inc_, which has just adopted a new backup policy. 

You will be responsible for validating the new backup process by performing the following two tests:

  - Use a backup to restore lost patient files. 

  - Create two new files and perform an incremental backup. 

You will use the following process to test the new restoration procedure:

- List and verify the existing files in the `testenvir` directory.
- Create a **level 0** backup on Sunday containing the entire `testenvir` directory.
- Simulate a cyber attack by deleting the `patient` directory from the `testenvir` parent folder.
- Verify the `patient` directory is missing.
- Restore the missing `patient` directory from the incremental backup.
- List and verify the `patient` directory to verify the restoration was successful.
- Create two new files in the `patient` directory.
- Create an incremental backup on Monday and verify that the new `patient` files have been properly backed up.

Finally, your team will conclude this exercise by reviewing file attributes as a results of the backup process.

### Lab Environment

If you are not already logged on, log into the lab environment using the following credentials:

  - Username: `sysadmin`  
  - Password: `cybersecurity`

### Instructions

1. Move into the `~/Documents/epscript/testenvir` directory and list the contents.

2. In your `~/Documents/epscript` directory, create the level 0 backup of the `testenvir` directory, which contains the `doctor`, `patient`, and `treatment` directories.

   - Change back into the `epscript` directory:

      - Run `cd ../`

   - Create the level 0 backup of the `testenvir` directory.

3. View and verify the contents of the **level 0** backup by using `tar`.

   - What is the status of the files in the backup?

     * What does **`D`** indicate?

     * What does **`Y`** indicate?

4.  Next, we'll simulate a natural disaster or cyber attack by removing the `patient` directory.

     - From the `~/Documents/epscript` directory:

       - Run `rm -r testenvir/patient/`

    - Verify that the `patient` directory is removed.

       - Run `ls -l testenvir/`

   - Your output should look similar to the following. Notice that the `patient` directory is missing.

      ```
      total 8
      drwxr-xr-x 2 sysadmin sysadmin 4096 Jul 14 10:14 doctor
      drwxr-xr-x 3 sysadmin sysadmin 4096 Jul 14 10:14 treatment
      ```

5. Restore the missing patient directory from the `epscript_back_sun.tar` backup to the `~/Documents/epscript/testenvir/patient/` directory.

   - Make sure you're in the `epscript` directory:

     - Run `cd ~/Documents/epscript`

   - Restore the missing **patient** directory.

   - Verify that the files have been added to the `testenvir/patient` directory successfully.

      - Run `ls -l testenvir/`

    - If successful, the missing `patient` directory should be properly restored from the archive.

6. Before we create an incremental backup, we'll add new files. Let's add a couple of files to the  `patient` directory:

    - First, ensure your in the `cd ~/Documents/epscript/testenvir/patient/` directory.

      - Run `cd ~/Documents/epscript/testenvir/patient/`

    - Create a few of arbitrary files:

      - For example: `touch patient.0a.txt patient.0b.txt`

    - Verify the 

      - Run `ls -l`

    - Output should look similar to below. Notice the two new files `patient.0a.txt` and `patient.0b.txt` have been successfully created:

      ```
      total 284
      -rw-r--r-- 1 sysadmin sysadmin      0 Aug 13 12:27 patient.0a.txt
      -rw-r--r-- 1 sysadmin sysadmin      0 Aug 13 12:27 patient.0b.txt
      -rw-r--r-- 1 sysadmin sysadmin   6236 Jul 14 10:14 patients.10.csv
      -rw-r--r-- 1 sysadmin sysadmin   6250 Jul 14 10:14 patients.11.csv
      ```

7. Assume it's Monday. Now, we'll create an incremental backup that will include our newly created patient documents.

   - Change back to the `~/Documents/epscript` directory:

     - Run `cd ~/Documents/epscript`

   - Create an incremental backup for Monday.

   - List the contents of the `epscript_back_mon.tar` incremental backup and verify that the new files have been archived.

      - What is the status of the files in the incremental backup?

For additional reference, consider the following:  

  - [Manpages: backup-manager](<http://manpages.ubuntu.com/manpages/bionic/man8/backup-manager.8.html>) 
  - [Amanda.org](<http://www.amanda.org/>)


#### Bonus Review Questions

1. Briefly describe the difference between a full and incremental backup.

2. If you have a backup schedule of Monday, Tuesday, Wednesday, Thursday, and Friday:  

    - On what day would you schedule a level 0 backup to be done?

    - In what order should the backups be applied to restore a system that was completely lost after an attack?

3. What command would you use to create a level 0 backup of `archive/home/user1`? 

4. What command would you use to list the contents of an incremental backup?

5. After listing the contents of an incremental backup, what do the following letters indicate?

    - **`Y`** indicates that _______.

    - **`N`** indicates that _______.

    - **`D`** indicates that _______.


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
