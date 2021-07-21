## Solution Guide: Log Auditing

The goal of this activity was to use `audit` to create an event monitoring system that specifically generates alerts when new user accounts are created and/or modified. Typically, attackers will create a user account for themselves to establish persistence in addition to using cron to keep their backdoors open. Using a tool like `auditd` helps mitigate against malicious account creation though monitoring and recording to disk file audit information.

### Solutions

1. Install `auditd` using the `apt` package manager.

   - Run:  `sudo apt install auditd -y`
  
2. Verify the `auditd` service using the `systemctl` command.

   - Run `systemctl status auditd`

      ```bash
      ● auditd.service - Security Auditing Service
      Loaded: loaded (/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
      Active: active (running) since Sun 2019-10-27 15:01:58 PDT; 2min 27s ago
        Docs: man:auditd(8)
              https://github.com/linux-audit/audit-documentation
      Main PID: 5150 (auditd)
      Tasks: 2 (limit: 2290)
      Group: /system.slice/auditd.service
              └─5150 /sbin/auditd
      ```

3. Configure the `/etc/audit/auditd.conf` file with the following parameters using `sudo`:

    - Run `sudo nano /etc/audit/auditd.conf`

    - Log file location should already be `/var/log/audit/audit.log`.

      ```bash
      log_file = /var/log/audit/audit.log
      ```

    - Number of retained logs is `10`

      ```bash
      num_logs = 10
      ```

    - Maximum log file size is `50`.

      ```bash
      max_log_file = 50
      ```

4. Check to make sure you're no other rules exist:

   - Run `sudo auditctl -l`

      ```bash
      No rules
      ```

5. Create a rule that will monitor both `/etc/passwd` and `/etc/shadow` for any changes:

    - Run `sudo nano /etc/audit/rules.d/audit.rules`, and add:

      - `-w /etc/shadow -p wa -k shadow`
      - `-w /etc/passwd -p wa -k passwd`

6. Restart the `auditd` deamon.

   - Run `sudo systemctl restart auditd`
   
7. Check to verify the new rules have taken place.

    - Run `sudo auditctl -l` to see the output:

      ```bash
      -w /etc/shadow -p wa -k shadow
      -w /etc/passwd -p wa -k passwd
      ```

8.  Add a new rule to audit the `/usr` directory.

    - Run `sudo auditctl -w /usr/`

    - Verify the new rule by run `sudo auditctl -l`

        ```bash
        -w /etc/shadow -p wa -k shadow
        -w /etc/passwd -p wa -k passwd
        -w /usr -p rwxa
        ```

9. Perform a search to look for failed user authentications.

   **Note**: Your `aureport` results will vary from these solutions results due to the nature of individual machine usage.

    - Run `sudo aureport -au`

        ```bash
        Authentication Report
        ============================================
        # date time acct host term exe success event
        ============================================
        1. 10/27/2019 15:05:57 sysadmin ? /dev/pts/1 /usr/bin/sudo yes 50
        2. 10/27/2019 15:06:18 root ? /dev/pts/1 /bin/su yes 56
        3. 10/27/2019 15:09:02 root ? /dev/pts/0 /bin/su yes 68
        4. 10/27/2019 15:32:30 sysadmin ? /dev/pts/0 /usr/bin/sudo yes 181
        ```

    - Run `sudo -k`

10. Perform a `sudo su` three times using the wrong password, then run the same report again.

    - **Note:** Notice the following: on Line 7, `no 391`, on Line 8, `no 392`, on Line 9, `no 393`. The `no` means failed login attempt.

    - `sudo aureport -au`

      ```bash
      Authentication Report
      ============================================
      # date time acct host term exe success event
      ============================================
      1. 10/27/2019 15:05:57 sysadmin ? /dev/pts/1 /usr/bin/sudo yes 50
      2. 10/27/2019 15:06:18 root ? /dev/pts/1 /bin/su yes 56
      3. 10/27/2019 15:09:02 root ? /dev/pts/0 /bin/su yes 68
      4. 10/27/2019 15:32:30 sysadmin ? /dev/pts/0 /usr/bin/sudo yes 181
      5. 10/27/2019 15:51:31 sysadmin ? ? /usr/lib/policykit-1/polkit-agent-helper-1 yes 335
      6. 10/27/2019 15:55:48 root ? /dev/pts/0 /bin/su yes 375
      7. 10/27/2019 15:56:13 sysadmin ? /dev/pts/0 /usr/bin/sudo no 391
      8. 10/27/2019 15:56:17 sysadmin ? /dev/pts/0 /usr/bin/sudo no 392
      9. 10/27/2019 15:56:21 sysadmin ? /dev/pts/0 /usr/bin/sudo no 393
      10. 10/27/2019 15:56:41 sysadmin ? /dev/pts/0 /usr/bin/sudo yes 395
      11. 10/27/2019 15:56:50 root ? /dev/pts/0 /bin/su yes 410
      12. 10/27/2019 15:59:34 sysadmin ? /dev/pts/0 /usr/bin/sudo yes 463
      ```

11. Create a new user, `criminal`, then perform search for account modifications.

   - Run `sudo useradd criminal`

   - Run `sudo aureport -m`

      ```bash
      Account Modifications Report
      =================================================
      # date time auid addr term exe acct success event
      =================================================
      1. 10/27/2019 15:33:17 1000 ubuntu pts/1 /usr/sbin/useradd criminal yes 190
      2. 10/27/2019 15:33:17 1000 ubuntu pts/1 /usr/sbin/useradd ? yes 191
      ```

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  