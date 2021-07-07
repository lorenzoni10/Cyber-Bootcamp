## Solution Guide: Permissions

Start by inspecting the file permissions on each of the files listed, and determine if they are already set correctly or if you need to change the permissions.

  - Run: `ls -l <file1> <file2> <file3>`

1. Set permissions `600` on `/etc/shadow` (`rw` for root only).

   - Running `ls -l /etc/shadow` indicates that the permissions are set to `640`. 

   - Run: `sudo chmod 600 /etc/shadow`

2. Set permissions `600` on `/etc/gshadow` (`rw` for root only).

   - Running `ls -l /etc/gshadow` indicates that the permissions are set to `640`.

   - Run: `sudo chmod 600 /etc/gshadow`

3. Set permissions `644` on `/etc/group` (`rw` for root and `r` for all others).

   - Running `ls -l /etc/group` indicates that the permissions are already set to `644`.

4. Set permissions `644` on` /etc/passwd` (`rw` for root and `r` for all others).

   - Running `ls -l /etc/passwd` indicates that the permissions are already set to `644`.
  
**Bonus**  

5. Verify all accounts have passwords.

   - Running `sudo grep root /etc/shadow` indicates that the root user doesn't have a password.

   - We want to verify that each account has a password hash and not a `!` in the second field of each listing in the `/etc/shadow` file. `!` indicates that there is no password set for that user.

   - Notice that if simply grep for '!', we can quickly determine if other users have no password, rather than manually inspecting the shadow file.
    `sudo grep "!" /etc/shadow`


6. Verify that no users have UID of `0` besides `root`. If you find one that does, change it's UID to any value greater than `1000`.

  - We are examining the third field of each line in the `/etc/passwd` file. Only the root user should have a `0` in this field, and everything else should have a value greater than `1000` if it's a person, and less than `1000` if it's a service user.

  - Running `sudo less /etc/passwd` indicates that the user `adam` also has a UID of `0`.

  - Note: A cleaner but trickier solution is to run `grep "x:0" /etc/passwd`.  This requires first recognizing that the user ID is preceded by "x:"

  - Run `sudo nano /etc/passwd` to change the UID from `0` to something greater than `1000`, and that is __not in use__ by another user!

7. Add a list of your findings to your research directory.

   - Run `nano ~/research/permissions.txt` to create a document to store your findings, including everything from above.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
