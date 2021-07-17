
## Solution Guide: Scheduling Backups and Cleanups

Completing this activity required the following tasks: 

- Moving the `backup.sh` and `update.sh` scripts to their corresponding system-wide `cron` directories. **Bonus** includes moving `cleanup.sh`.

- Creating `lynis` scripts to perform security scans.

Move the scripts you wrote in the previous exercise to the appropriate `cron` directories in `/etc`. Specifically, your scripts should run at the following intervals:

- `backup.sh` should run weekly.
- `update.sh` should run weekly.

Navigate to your scripts folder and copy them to the corresponding `/etc` cron directory:

- `cd ~/Security_scripts`  

- `sudo cp backup.sh /etc/cron.weekly`

- `sudo cp update.sh /etc/cron.weekly`

In addition to scheduling the above tasks, you should perform regular security scans to ensure your system hasn't been compromised. 

- Create a script called `lynis.system.sh` in your `~/Security_scripts` directory. Write a command that will run a full-system scan using `lynis` every week that saves the results in `/tmp/lynis.system_scan.log`. Run:

    - `cd` to go to your home folder

    - `nano lynis.system.sh`

    ```bash
    #!/bin/bash
    lynis audit system >> /tmp/lynis.system_scan.log
    ```

- Create a script called `lynis.partial.sh`. Write a command that will use `lynis` to run daily scans for the test groups: `malware`, `authentication`, `networking`, `storage`, and `filesystems` that saves the results in `/tmp/lynis.partial_scan.log`. Run:

    - `nano lynis.partial.sh`

    ```bash
    #!/bin/bash
    lynis audit --tests-from-group malware,authentication,networking,storage,filesystems >> /tmp/lynis.partial_scan.log
    ```

- Then add both `lynis` scripts to the `root` crontab to create the tasks.

First:

  - Ensure that the scripts are executable as follows:

Run:

  - `chmod +x lynis.system.sh`
  - `chmod +x lynis.partial.sh`

 Run:

  - `sudo crontab -e`, then add to the bottom:

  ```bash
  @weekly lynis.system.sh
  @daily lynis.partial.sh
  ```

- To use the `/etc/cron.<time>` route, run:

  - `sudo cp lynis.system.sh /etc/cron.weekly`

  - `sudo cp lynis.partial.sh /etc/cron.daily`

#### Bonus

A. Move the scripts you wrote in the previous exercise to the appropriate `cron` directories in `/etc`. Specifically, your scripts should run at the following intervals:

  - `cleanup.sh` should run daily.

  Navigate to your scripts folder and copy them to the corresponding `/etc` cron directory:

  - `cd ~/Security_scripts`  

  - `sudo cp cleanup.sh /etc/cron.daily`

B. Explain why using scripts to run these commands is preferable to using a `crontab`.


    - Multiple commands can be configured to run inside of a single executable script. This is convenient because there is no need to edit the crontab directly. You only need to edit the script directly which will run during the next scheduled cron job.

    - Moving the `backup.sh`, `cleanup.sh`, and `update.sh` scripts to their corresponding system-wide `cron` directories.

    - Creating `lynis` scripts to perform security scans.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
