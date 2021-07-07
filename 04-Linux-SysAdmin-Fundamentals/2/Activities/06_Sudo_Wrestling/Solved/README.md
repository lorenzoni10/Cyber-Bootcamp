## Solution Guide: `Sudo` Wrestling

1. Print the name of your current user to the terminal.
  - Run `whoami`

2. Determine what sudo privileges the admin user has.
  - Run `sudo -l`

3. Record in a text document inside your research folder what `sudo` access the users on the system have.
  - Run  `sudo -lU <username>  >> ~/research/sudo_access.txt`

4. Find a user that has `sudo` access for the `less` command and complete the following:
  
  - Run: `sudo -lU <username>`

    - Note: Alternatively, we can run `sudo grep less /etc/sudoers`

  - Switch to that user by using the password you found in the previous activity.
    - Run: `sudo su max` (password: `welcome`)

  - Verify the vulnerability by dropping from `less` into a root shell.
    - Run `sudo less shopping_list.txt` _then_ `!bash`.

  - Exit back to the command line.
    - Run `exit` to exit back into `less`. Run `q` to quit `less`.

  - Search this user's files for anything suspicious.
    - Run: `ls -a /home/max` to reveal a copy of `.rev_shell.sh`.

  - Exit that user.
    - Run: `exit`

**Bonus**

5. From the sysadmin user, switch to the root user.
  - Run: `sudo su`

6. Check the `sudoers` file to determine if there are any users listed with `sudo` privileges.
   - Run: `less /etc/sudoers`

   - Note:  `grep less /etc/sudoers` is a better command!

   - Note: Since we are root, we don't need sudo!

7. Edit the `sudoers` file so that only the admin user has access.
   - Run `visudo` and remove user `max` from `sudo` access.
  
   - You should remove the following line:

      ```bash
      max  ALL=(ALL) /usr/bin/less
      ```
  
8. Check that your changes to the `sudoers` file worked.
   - Run `su max` _and_ attempt `sudo less somefile`.

Note: Remember, it's always better to use `sudo` as opposed to `su`.  We use `su` here only as a demonstration.

- :warning: **Trouble Shooting:** If the `sudoers` file becomes damaged, it could stop you from using `sudo` at all. To troubleshoot this, follow the thread here: [Ask Ubuntu: How to modify an invalid etc sudoers file](https://askubuntu.com/questions/73864/how-to-modify-an-invalid-etc-sudoers-file)


---


© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
