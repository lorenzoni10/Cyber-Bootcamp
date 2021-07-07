## Activity File: Permissions

During the last activity, we cleaned up the system's groups and users and removed all the malicious users. We also removed users from the `sudo` group and found and removed a rogue group.

Your senior administrator now wants you to secure a few important files and directories. Recall that during our scavenger hunt yesterday, we talked about the sensitive files on the system that contain all the users (`/etc/passwd`), the passwords (`/etc/shadow`), and the groups (`/etc/group`).

This activity will give you an opportunity to practice inspecting and setting file permissions on these sensitive files. Use the checklist provided by your senior administrator in the **Instructions** section for information on which files to inspect and modify permissions for.

You'll use the same lab environment you used in the previous exercises:
- Username: `sysadmin` 
- Password: `cybersecurity`

### Instructions

Your senior administrator has asked you to complete the following:

1.  Set permissions on `/etc/shadow` to allow only `root` read and write access.

2. Set permissions on `/etc/gshadow` to allow only `root` read and write access.

3. Set permissions on `/etc/group` to allow `root` read and write access, and all others read access only.

4. Set permissions on `/etc/passwd` to allow `root` read and write access, and all others read access only.

**Bonus**

5. Verify all accounts have passwords.

6. Recall that if any user has the UID of `0`, the system thinks they are `root`. Verify that no users have UID of `0` besides `root`. If you find one that does, change the user's UID to any value greater than `1000`.

7. Provide a list of all permission changes that you make in a text file in your research directory.

Attempt to complete these tasks on your own. If you need help, refer to the further instructions below.

---

### Further Instructions

- Start by inspecting the file permissions on each of the files listed. Determine if they are already set correctly or if you need to change the permissions.

- Use [this web Resource](https://askubuntu.com/questions/518259/understanding-chmod-symbolic-notation-and-use-of-octal) if you get stuck.

- Verify that all accounts have passwords. 
    - If you get stuck, google how to determine if an account has a password on a Linux system.

- Verify that only the root user has a UID of `0`. 
  
   _**Hint:** This is similar to verifying the password._

- Document all of your findings into a file using `nano`. Keep that file in your research directory.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
