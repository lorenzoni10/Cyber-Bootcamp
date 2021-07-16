## Solution Guide: Creating and Restoring Backups with `tar`

The goal of this activity was to create a *full backup* of the epscript directories and files, including file permissions, owner, size of file, and date and time information.  They verified the archive for errors after writing it and the output from the command was saved to a text file. In the second part of the activity, they located the correct archive to restore the patient directory and files

Completing this activity required the following steps:

- Creating the name of the tar archive using the YYYMMDD ISO 8601 standard.

- Creating a full backup using the tar create option.

- Printing the full listing for each file, including the name, file permissions, and owner information.

- Verifying the archive after it was written to check for errors.

- Creating a file of the output of the `tar` command for later review by the SysOps team.

- Listing the contents of the archive to determine what it contains.

- Creating a directory to restore the patient directories and files. 

- Extracting only the patient directory and files to the directory for review before restoring the files to the E-Prescription Treatment system.

- **Bonus**: Using the `grep` command to search the archive for two patient names.

Completing these steps will ensure that our archive has the correct data, no errors, and can be used in the event of a malware attack to restore the E-Prescription Treatment system.

#### Part 1 Walkthrough

1. First, we move to the `~/Documents/epscript` directory.

   - `cd ~/Documents/epscript/`  

2. List the directories and files located there:
   
   - Run `ls -l epscript`

   - Output should look similar to the following: 
  
     ```
     drwxr-xr-x  2   sysadmin  sysadmin  4096    Jul 16   14:02   doctors
     drwxr-xr-x  2   sysadmin  sysadmin  4096    Jul 16   14:02   patients
     drwxr-xr-x  2   sysadmin  sysadmin  4096    Jul 16   14:00   treatments
     ```  
      - Here we see three directories `doctors`, `patients`, and `treatments`.

   - Run `ls -l epscript/doctors/` to list the contents of the `doctor` directory and display the contents, which are `.csv` files. 


   - Output should read:

      ```bash
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:16   doctor10.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:12   doctor1.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:13   doctor2.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:15   doctor3.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:15   doctor4.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:15   doctor5.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:15   doctor6.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:15   doctor7.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:16   doctor8.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   14:16   doctor9.csv
      -rw-r--r--  1   sysadmin  sysadmin  75962   Jul 16   13:22   doctor.csv
      ```

   - List the contents of the `patient` and `treatment` directories and display the contents of the other `.csv` files.

      - Run `ls -l epscript/patients/` 

      - Run `ls -l epscript/treatments/`

3. The archive filename is created using the ISO 8601 standard.

    - Using the standard format of `[YYYMMDD][filename].tar`, our archive filename is: `20190505epscript.tar`.

    - [ISO](<https://www.iso.org/home.html>) stands for International Organization for Standards. It publishes international standards such as the [ISO/IEC 27032:2012](<https://www.iso27001security.com/html/27032.html>) which is a standard for internet security issues.

    - Emphasize that [ISO 8601 for filenames](<https://wadegibson.com/why-you-should-use-the-iso-date-format/>) is important because:

      - The naming convention is recognized internationally.  
      
      - Files prefixed with an ISO date will automatically sort *oldest to newest* under the default alphabetical sort.

4. Write a `tar` command that creates an archive with the following characteristics:

    - The syntax is: `tar [option(s)] [archive_filename] [objects_to_archive]`
    
    - Command: `tar cvvWf 20190505epscript.tar epscript/ > 20190505epscript.txt`

    - Syntax breakdown:
      - `tar`: the name of the command.
      - `c`: creates the archive.
      - `vv`: **very verbose**, or verbosity level 2, prints the full file specification for each file in the archive.  
      - `W`: verifies the archive after writing it.
      - `f`: specifies the **filename** for our archive.
      -  `20190505epscript.tar`: the archive filename that we created following the ISO 8601 guidelines.
      - `epscript/*`: the directory that contains all of the files to archive. We use the asterisk `*` wildcard to denote that we want everything in this directory and all of its subdirectories.
      - `> 20190505epscript.txt`: saves the output of the command to the the `20190505epscript.txt` text file.

5. Using the `less` command, review the output of the `20190505epscript.txt` file:

    - Run `less 20190505epscript.txt`

    - Output should look similar to the following snippit:

      ```bash
      drwxr-xr-x  sysadmin/sysadmin   0       2019-07-16  15:11   epscript
      drwxr-xr-x  sysadmin/sysadmin   0       2019-07-16  15:24   epscript/treatment
      -rw-r--r--  sysadmin/sysadmin   192273  2019-07-16  15:24   epscript/treatment/treatments10.csv
      ```
    - **Note**: Notice that the entire directory structure remains intact as compared to the original directory structure.

#### Part 2 Walkthrough 

1. Move to and list the contents of the `~/Documents/epscript/backup` directory.

    - Run `cd ~/Documents/epscript/backup`

    - Run `ls -l`

    - Your output should look similar to this:

        ```
        -rw--r-r--  1   sysadmin  sysadmin  4341760    Jul 17   01:45   20190814epscript.tar
        ```

    - We'll use the `20190814epscript.tar` file to search for the patient information.


2. List the contents of the `20190814epscript.tar` and pipe the output to the screen.

   - Run: `tar tvvf 20190814epscript.tar | less`

   - Output should look similar to below:

     ```
     drwxr-xr-x  sysadmin/sysadmin   0       2019-07-16  15:11   epscript
     drwxr-xr-x  sysadmin/sysadmin   0       2019-07-16  15:24   epscript/treatment
     -rw-r--r--  sysadmin/sysadmin   192273  2019-07-16  15:24   epscript/treatment/treatments10.csv
     ```

3. Extract the patient files from the archive, test for errors, and save them in the `patient_search` directory. 

   - The general syntax of the command is: `tar [options][archive_name][option][option][save_directory][objects_to_archive]`

   - In the `~/Documents/epscript/backup` directory, make a new directory called `patient_search`.

     - Run  `sudo mkdir patient_search`

     - Run  `sudo tar xvvf 20190814epscript.tar -C patient_search/ epscript/patients`

   - Syntax breakdown:

      - `xvvf`: the options.
      - `20190814epscript.tar`: the archive name. 
      - `-C`: saves the indicated patient directory and its files. 
      - `patient_search/`: the indicated directory.
      - `epscript/patients`: the directory that contains the patient files.  We are extracting files from this directory in the `tar` archive.

4. Verify that the patient files were extracted to the `patient_search` directory:

   - Run  `ls -l patient_search/epscript/patients`

    - Your output should look similar to this:

    ```
    -rw-r--r-- 1 sysadmin sysadmin  12193 Aug 14  2019 patients.10.csv
    -rw-r--r-- 1 sysadmin sysadmin  12334 Aug 14  2019 patients.1.csv
    -rw-r--r-- 1 sysadmin sysadmin  12534 Aug 14  2019 patients.2.csv
    -rw-r--r-- 1 sysadmin sysadmin  12398 Aug 14  2019 patients.3.csv
    ```

#### Bonus
This step would normally precede step 3 above.

5. Use `grep` to find two patient's, **Mark Lopez** and **Megan Patel**, file information located in the archive. 
    
    Note: It is generally best practice to look inside the archive, prior to restoring data, in order to ensure that the files you are looking for are actually there. This step would usually precede Step 3. 


   - Perform a search within the `~/Documents/epscript` directory for **Mark Lopez** patient records:

      - Move into the directory: `cd ~/Documents/  epscript`  

     - Ensure archive has been extracted for viewing: `tar xvf 20190814epscript.tar`

     - Search: `grep -R "Mark,Lopez" epscript/`   

   - The output should look similar to the following:

      ```
      809,Mark,Lopez,male,O,31,577.511.1054x23935,jeffrey93@jones.net,model,"673 Schultz Spur Apt. 244
      809,Mark,Lopez,male,O,31,577.511.1054x23935,jeffrey93@jones.net,model,"673 Schultz Spur Apt. 244
      ```

   - Within the same directory, perform a search for **Megan Patel** patient records as follows:

     - Run `grep -R "Megan,Patel" epscript/`   

     - The output should look similar to below:

        ```
        699,Megan,Patel,female,AB,43,001-684-391-7956,pjohnson@gmail.com,develop,"53082 Lopez IslandChavezchester, CT 11475"
        699,Megan,Patel,female,AB,43,001-684-391-7956,pjohnson@gmail.com,develop,"53082 Lopez Island
        ```

**Supplemental Reading:** Here is an article that highlights how a hacker steals millions of medical records to sell on the dark web.

  - [CBS News: Hackers Steal Medical Records, Sell Them on Dark Web]((<https://www.cbsnews.com/news/hackers-steal-medical-records-sell-them-on-dark-web/>))


---

© 2020 Trilogy Education Services, a 2U, Inc. brand.  All Rights Reserved.