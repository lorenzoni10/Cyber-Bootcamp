
## Activity File: Scheduling Backups and Cleanups

In this exercise, you remain in your role as a junior administrator at Rezifp Pharma Inc. 

- Now that you've developed scripts to keep the system clean, up-to-date, and properly backed up, the senior security manager has requested that you begin using system-wide `cron` directories to schedule your scripts. 

- Additionally, you have been asked to schedule regular security scans with Lynis.

### Instructions

1.  Move the following scripts you wrote in the previous exercise to the appropriate `cron` directories in `/etc`. Specifically, your scripts should run at the following intervals:

    - `backup.sh` should run weekly.
    - `update.sh` should run weekly.

2. In addition to scheduling the above tasks, you should perform regular security scans to ensure your system hasn't been compromised. 

    - Create a script called `lynis.system.sh` in your `~/Security_scripts` directory. 

    - Write a command that will run a full-system scan using Lynis every week, and saves the results in `/tmp/lynis.system_scan.log`.

3. Create a script called `lynis.partial.sh`. 

    - Write a command that will use `lynis` to run daily scans for the test groups: `malware`, `authentication`, `networking`, `storage`, and `filesystems`, and saves the results in `/tmp/lynis.partial_scan.log`.

4. Add both `lynis` scripts that you just wrote to the `root` crontab to create the tasks.

**Bonus**: 
 
 - **A**.  Move the following scripts you wrote in the previous exercise to the appropriate `cron` directories in `/etc`. Specifically, your scripts should run at the following intervals:

    - `cleanup.sh` should run daily.

 - **B**. Explain why using scripts to run these commands is preferable to using a `crontab`.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  