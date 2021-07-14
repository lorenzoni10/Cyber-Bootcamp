## Activity File: Log Auditing

In this activity, you are a junior administrator at Rezifp Pharma Inc. The company maintains a large database of data associated with patients, doctors, and their treatments. These files are maintained on a local server.

- The local server was hit with MedusaLocker, a nasty ransomware attack that left all the organization’s hard drives crypto-locked. 

- Under extreme pressure to restore medical services, your organization decided to pay the ransom using Bitcoin. The drives were subsequently unlocked and all data was recovered. However, you noticed that new user accounts have been created. You’ve already confirmed that these users do not exist within your company. 

- This implies that MedusaLocker left behind a specific type of malware, known as a logic bomb, designed to create persistent backdoor access into the system by creating new user accounts.

  - The term comes from the idea that a logic bomb “explodes” when it is triggered by a specific event. Events could be a certain date or time, a particular record being deleted from a system, or the launching of an infected software application.

- To help mitigate against future ransomware attacks, you have decided to create an event monitoring system that specifically generates alerts when new user accounts are created and/or modified. Typically, attackers will create a user account for themselves to establish persistence, in addition to using `cron` to keep their backdoors open.

### Instructions

1. Install `auditd` using the `apt` package manager.

2. Verify the `auditd` service using the `systemctl` command.

3. Configure the `/etc/audit/auditd.conf` file with the following parameters using `sudo`:

    - Log file location is `/var/log/audit/audit.log`.

    - Number of retained logs is `10`

    - Maximum log file size is `50`.

4. Check to make sure there are no existing rules.

5. Create a rule that will monitor `/etc/passwd` and `/etc/shadow` for any changes.

6. Restart the `auditd` daemon.

7. Check to verify the new rules have taken place.

8. Add a new rule to audit the `/usr` directory.

    - Verify the new rule by listing `auditcl` rules.

9. Perform a search in the authentication report for user authentication attempts.

    -  Make sure to disable your current `sudo` access with `sudo -k`. This option revokes your current `sudo` session, requiring you to have to enter your password on your next `sudo` command.

10. Perform a `sudo su` three times using the wrong password, then run the same report again.

11. Create a new user, `criminal`, then perform a search for account modifications.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  