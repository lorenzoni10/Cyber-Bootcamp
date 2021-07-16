## Solution Guide: Restoring Data with Incremental Backups

### Incremental Backup Restoration

1. Move into the `~/Documents/epscript/testenvir` directory and list the contents.

    - Run `cd ~/Documents/epscript/testenvir`

    - Run `ls -l`

     Notice the `doctor`, `patient`, and `treatment` directories.

    ```
    total 12
    drwxr-xr-x 2 sysadmin sysadmin 4096 Jul 14 10:14 doctor
    drwxr-xr-x 2 sysadmin sysadmin 4096 Jul 14 10:14 patient
    drwxr-xr-x 3 sysadmin sysadmin 4096 Jul 14 10:14 treatment
    ```

2. In your `~/Documents/epscript` directory, create the level 0 backup of the `testenvir` directory, which contains the `doctor`, `patient`, and `treatment` directories.

   - Move back into the `epscript` directory:

      - Run `cd ../`

   - Create the level 0 backup of the `testenvir` directory by running:

      - Run `tar cvvWf epscript_back_sun.tar --listed-incremental=epscript_backup.snar --level=0 testenvir`

    - Your very verbose output should look similar to this:

      ```
      tar: testenvir: Directory is new
      tar: testenvir/doctor: Directory is new
      tar: testenvir/patient: Directory is new
      tar: testenvir/treatment: Directory is new
      tar: testenvir/treatment/backup: Directory is new
      drwxr-xr-x sysadmin/sysadmin 0 2020-07-14 10:14 testenvir/
      drwxr-xr-x sysadmin/sysadmin 0 2020-07-14 10:14 testenvir/doctor/
      drwxr-xr-x sysadmin/sysadmin 0 2020-07-14 10:14 testenvir/patient/
      drwxr-xr-x sysadmin/sysadmin 0 2020-07-14 10:14 testenvir/treatment/
      ```

3. We can view and verify the contents of the **level 0** backup by using `tar` as follows:

   - Run `tar tvvf epscript_back_sun.tar --incremental | less`
     
       - Tap the `tab` button on the keyboard to advance the screen one page at a time. 
       - Tap the `enter` key to advance one line at a time.

   - Status of the files in the backup should look similar to the following:

      ```
      drwxr-xr-x sysadmin/sysadmin 29 2020-07-14 10:14 testenvir/
      D doctor
      D patient
      D treatment

      drwxr-xr-x sysadmin/sysadmin 325 2020-07-14 10:14 testenvir/doctor/
      Y doctors.1.csv
      Y doctors.10.csv
      Y doctors.11.csv

      ...
      ...

      drwxr-xr-x sysadmin/sysadmin 346 2020-07-14 10:14 testenvir/patient/
      Y patients.1.csv
      Y patients.10.csv
      Y patients.11.csv

      ...
      ...

      drwxr-xr-x sysadmin/sysadmin 396 2020-07-14 10:14 testenvir/treatment/
      D backup
      Y treatments.1.csv
      Y treatments.10.csv
      Y treatments.11.csv

      ...
      ...
      ```

   - What is the status of the files in the backup?

     * **`D`** indicates directories.

     * **`Y`** indicates that these file are contained in the `epscript_back_sun.tar` archive.

4. Simulate a natural disaster or cyber attack by removing the `patient` directory.

    - From the `~/Documents/epscript` directory:

      - Run `rm -r testenvir/patient/`

    - Verify that the `patient` directory is removed:

       - Run `ls -l testenvir/`

    - Your output should look similar to the following. Notice that the `patient` directory is missing.

      ```
      total 8
      drwxr-xr-x 2 sysadmin sysadmin 4096 Jul 14 10:14 doctor
      drwxr-xr-x 3 sysadmin sysadmin 4096 Jul 14 10:14 treatment
      ```

5. Restore the missing patient directory from the `epscript_back_sun.tar` backup to the `~/Documents/epscript/testenvir/patient/` directory.

   - Make sure your in the `epscript` directory:

     - Run `cd ~/Documents/epscript`

   - Restore the missing **patient** directory:

     - Run `tar xvvf epscript_back_sun.tar -R -C ~/Documents/epscript/ testenvir/patient/`

   - Your very verbose output should look similar to below:

     ```
     block 5: drwxr-xr-x sysadmin/sysadmin 346 2020-07-14 10:14 testenvir/patient/
     block 341: -rw-r--r-- sysadmin/sysadmin 6329 2020-07-14 10:14 testenvir/patient/patients.1.csv
     block 355: -rw-r--r-- sysadmin/sysadmin 6236 2020-07-14 10:14 testenvir/patient/patients.10.csv
     block 369: -rw-r--r-- sysadmin/sysadmin 6250 2020-07-14 10:14 testenvir/patient/patients.11.csv
     block 383: -rw-r--r-- sysadmin/sysadmin 6311 2020-07-14 10:14 testenvir/patient/patients.12.csv
     ```

   - Verify that the files have been added to the `testenvir/patient` directory successfully.

     - Run `ls -l testenvir/`

   - Your output should look similar to the following:

      ```  
      total 12
      drwxr-xr-x 2 sysadmin sysadmin 4096 Jul 14 10:14 doctor
      drwxr-xr-x 2 sysadmin sysadmin 4096 Jul 14 10:14 patient
      drwxr-xr-x 3 sysadmin sysadmin 4096 Jul 14 10:14 treatment
      ```

     - The missing `patient` directory has been properly restored from the archive.

6. Before we create an incremental backup, we'll create some files in the `patient` directory:

    - Make sure your in the `cd ~/Documents/epscript/testenvir/patient/` directory.

      - Run `cd ~/Documents/epscript/testenvir/patient/`

    - Create a couple of arbitrary files:

      - Run `touch patient.0a.txt patient.0b.txt`

    - Verify that the files have been added:

      - Run `ls -l`

    - Output should look similar to below. Notice the two new files `patient.0a.txt` and `patient.0b.txt` have been successfully created:

      ```
      total 284
      -rw-r--r-- 1 sysadmin sysadmin      0 Aug 13 12:27 patient.0a.txt
      -rw-r--r-- 1 sysadmin sysadmin      0 Aug 13 12:27 patient.0b.txt
      -rw-r--r-- 1 sysadmin sysadmin   6236 Jul 14 10:14 patients.10.csv
      -rw-r--r-- 1 sysadmin sysadmin   6250 Jul 14 10:14 patients.11.csv
      ```

7. Assume it's Monday. Now, we'll create an incremental backup that will include our newly created patient documents as follows:

   - Change back to the `~/Documents/epscript` directory:

     - Run `cd ~/Documents/epscript`

   - Create an incremental backup for Monday as follows:  

     - Run `tar cvvWf epscript_back_mon.tar --listed-incremental=epscript_backup.snar testenvir` 

   - List the contents of the `epscript_back_mon.tar` incremental backup and verify that the new files have been archived.

      - Run `tar tvvf epscript_back_mon.tar --incremental | less`

      - Your output should look similar to the following. Notice that our new patient files `patient.0a.txt` and `patient.0b.txt` have been successfully archived under the `testenvir/patient/` directory:

        ```
        drwxr-xr-x sysadmin/sysadmin 29 2020-08-13 12:05 testenvir/
        D doctor
        D patient
        D treatment


        drwxr-xr-x sysadmin/sysadmin 325 2020-07-14 10:14 testenvir/doctor/
        N doctors.1.csv
        N doctors.10.csv
        N doctors.11.csv
        N doctors.12.csv

        ...
        ...

        drwxr-xr-x sysadmin/sysadmin 378 2020-08-13 12:27 testenvir/patient/
        Y patient.0a.txt
        Y patient.0b.txt
        Y patients.1.csv
        Y patients.10.csv
        Y patients.11.csv

        ...
        ...

        drwxr-xr-x sysadmin/sysadmin 396 2020-07-14 10:14 testenvir/treatment/
        D backup
        N treatments.1.csv
        N treatments.10.csv
        N treatments.11.csv
        N treatments.12.csv

        ...
        ...
        ```

   - What is the status of the files in the incremental backup?

     - **`D`** indicates directories.

     - **`N`** indicates that the file was present in the directory at the time the archive was made. However, it was not added to the `epscript_back_mon.tar` archive because it had not changed since the last backup. 

     - **`Y`** indicates that the file is contained in the `epscript_back_mon.tar` archive.

#### Bonus Review Questions

1. What is the difference between a `full` and `incremental` backup?

    - A **full backup** saves every file on a hard drive. 
    - An **incremental backup** only saves the data that has changed since the last full backup.

2. If you have a backup schedule of Monday, Tuesday, Wednesday, Thursday and Friday:  

    - On what day would you schedule a level 0 backup to be done?

        - Monday

    - In what order should the backups be applied to restore a system that was completely lost after an attack?

        - Start with Monday, end with Friday. 

3. What command do you use to create a level 0 backup of `archive/home/user1`? 
    
    - `tar cvvWf backup.tar --listed-incremental=backup.snar --level 0 archive/home/user1`

4. What command would you use to list the contents of an incremental backup?

    - `tar tvvf backup.tar --incremental`

5. After listing the contents of an incremental backup, what do the following letters indicate:

    - **`Y`** indicates that the file is contained in the `backup.tar` archive.

    - **`N`** indicates that the file was present in the directory at the time the archive was made, but was not added to the `backup.tar` archive because it has not changed since the last backup.

    - **`D`** indicates the file is a directory.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
