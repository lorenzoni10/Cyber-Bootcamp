## Activity File: Creating and Restoring Backups with `tar`

### Part 1: Creating Backups with `tar`

In this two-part activity, you are a junior administrator at *Rezifp Pharma Inc.*

- The company conducts clinical trials on drugs for oncology, immunology, and vaccines.  In recent weeks, there have been a series of malware attacks. The company is now strengthening its backup activities.   

- In response to the malware attacks, your department has decided to create daily *full backups* of the files associated with the E-Prescription Treatment database, which is the main system for many departments. 

You have been tasked with:

- Creating a name for the `tar` archive using the department's standard naming convention.
 
- Creating daily full backups of the directories and files in the `~/Documents/epscript` directory.

- Printing the file permission, owner, size, date, and time for each file in the archive.
 
- Verifying the archive after it is written to check for errors.

- Creating a file containing the output of the `tar` command for later review by the SysOps team, which will check file structure, permissions, and errors.

#### Lab Environment

- To complete the activity, log into the lab environment using the following credentials:  
    - Username: `sysadmin` 
    - Password: `cybersecurity`

#### Instructions

1. Move to the `~/Documents/epscript` directory.

2. List the `epscript` directory contents and answer the following question:

    - What directories and files are located there? 

3. Prepare the directory for backup by standardizing the filenames:

    - Your department uses the [ISO 8601](https://www.cl.cam.ac.uk/~mgk25/iso-time.html) standard for representing the date in the naming convention for all archives.    
        
        - Using the standard for representing the date, YYYY-MM-DD, allows sysadmins to locate an archive quickly.

        - Use the date **May 5, 2019** and convert it to the ISO 8601 format *without dashes*.

    - Add the filename `epscript.tar` to the end of the ISO 8601 date.

    - What will be the archive name?

4.  Write a `tar` command that creates an archive with the following characteristics:

    - Recall that `[ISO_8601_date]epscript.tar` is the archive file name.

    - The file backup will include the `epscript` directory and includes all directories and files contained within it.

    - File permission, owner, size, and date and time information are recorded for each file in the archive.

    - The archive is **verified** after writing it, in order to validate the integrity of the data.

        **Hint:** This is a new option. [See the man page](http://man7.org/linux/man-pages/man1/tar.1.html).

    - The output from the `tar` command is written to the file `[archive_name].txt` for later review by the SysOps team to check file structure, permissions, and errors.

        - Note: `archive_name` is the `tar` archive name you created using `[ISO_8601_date]epscript.tar`.

5.  Using the `less` command, review the output of the `.txt` file.

      - What is displayed in the output file?

### Part 2: Restoring Backups with `tar`

The E-Prescription Treatment database was attacked and the database was taken offline. 

- Fortunately, the team had a recent full backup and was able to recover the database, making the system operational. However, a pharmacy technician noticed that some files in the Patient database were missing, and the team discovered that the wrong full backup was used. The system was taken offline again.

- It is critical that the missing patient files are restored as soon as possible. You have spoken to the pharmacy technician and received a list of the names of patients whose files are missing.  

You have been tasked to:

- List the contents of an archive to determine what it contains.

- Create a directory to restore the patient data for review.

- Extract only the patient files to the directory so they can be checked by the pharmacy technician. 

- Validate that the archive does not contain errors, using a new `tar` option.


### Instructions 

1. Move to the `~/Documents/epscript/backup` directory.

2. List the contents of the directory to display the `20190814epscript.tar` file. You will search this archive for the missing patient data.

3. Extract the patient directory from the `20190814epscript.tar` archive.  

    - Extract patient data to the `patient_search` directory in the `~/Documents/epscript/backup` directory.   

    - Test for any errors when extracting. This will check the integrity of the archive.

4. List the contents of the `patient_search` directory to check that the patient directory and files were extracted there.   

#### Bonus

5. View the specific patient directory and file information contained within the archive.

    - Use `grep` to find the following two patient's file information located in the archive:
      - Mark Lopez
      - Megan Patel



---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  