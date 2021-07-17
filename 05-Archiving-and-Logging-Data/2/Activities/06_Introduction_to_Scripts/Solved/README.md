## Solution Guide: Introduction to Scripting

Completing this activity required the following steps:

- Creating and moving into the directory, `~/Security_scripts`.

- Writing shell script `backup.sh` to automate archives and backups.

- Writing shell script `update.sh` to automate software package updates and removal.

- **Bonus:** Writing shell script `cleanup.sh` to automate the cleanup of cached files and generate a report of system resource usage.

- Testing the scripts by running them with bash using the `sudo ./<name of the script>.sh` command.

### Solutions

1. Begin by creating a directory to hold your scripts in `~/Security_scripts`. Then, move into this directory.

    - `mkdir -p ~/Security_scripts`  

    - `cd ~/Security_scripts`

2. `backup.sh`:

   - [See `backup.sh` for the complete script](backup.sh).

3. `update.sh` 

   - [See `update.sh` for the complete script](update.sh).
  
4. Make each of these custom scripts executable.

   - Run the following commands:
 
      - `chmod +x backup.sh`  

     - `chmod +x update.sh`  
    
5. Test the scripts by running them with bash using the `sudo ./<name of the script>.sh` command.

    - **Note**: Since we are interacting with system directories and processes such as `apt`, we need to use `sudo` for our scripts.

   - Run the following commands:

     - `sudo ./backup.sh`

      - When testing `backup.sh`, stop the script with `Ctrl + C`. Otherwise, it will take a long time to create a full backup of `/home`. We just want to see that it successfully runs. 

     - `sudo ./update.sh`

#### Bonus

6. `cleanup.sh`.

   - [See `cleanup.sh` for the complete script](cleanup.sh). 

   - Make each of these custom script executable.

     - Run the following commands at the command prompt as follows:

       - `chmod +x cleanup.sh`

   - Test the scripts by running them with bash using the `sudo ./<name of the script>.sh` command.

   - Since we are interacting with system directories and processes such as `apt`, we need to use `sudo` for our scripts.

     - `sudo ./cleanup.sh`

7.  - **apt cache**. After installing a package, the apt manager saves the package and dependencies in a cache folder.  They remain after installation unless the apt cache is cleared.
    -  **thumbnails cache**.  With each image file, your Linux distro creates a thumbnail when you view images in your file manager.  Thumbnails often remain for pictures that no loger exist. Therefore, this can be beneficial to clear old thumbails.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
