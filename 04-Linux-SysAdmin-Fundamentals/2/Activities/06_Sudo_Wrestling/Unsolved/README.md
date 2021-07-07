## Activity File: `Sudo` Wrestling

So far, we have been using administrator privileges to stop processes, install software, copy sensitive files, run programs, and edit configuration files.

Now that we know users had weak passwords, we want to make sure none of them have unauthorized `sudo` access. The next steps provided by your senior administrator have to do with locking access to the compromised system, including `sudo` access.

In this activity, you will explore the `sudo + less` exploit, shown in the previous demonstration, and check the compromised system in order to determine if it is vulnerable. You will also edit the `sudoers` file to remove `sudo` access. Being able to determine what users or processes have root access and why is a core skill for a system administrator.

- This activity will use the same lab environment that you have been using for the previous activities.   
  -  Username: `sysadmin`   
    - Password: `cybersecurity`

### Instructions

1. Print the name of your current user to the terminal.

2. Determine what `sudo` privileges the sysadmin user has.

3. In a text document inside your research folder, record what `sudo` access each of the users on the system has.

4. There is one user who has `sudo` access for the `less` command. Find that user and complete the following:
    - Switch to that user by using the password found in the previous activity.
    - Verify the vulnerability by dropping from `less` into a root shell.
    - Exit back to the command line.
    - Exit that user.
    
**Bonus**    

5. From the sysadmin user, switch to the root user.

6. Check the `sudoers` file to see if there are any users listed there with `sudo` privileges.

7. Edit the `sudoers` file so that only the administrator user has access.

8. Check that your changes to the `sudoers` file worked.

- :warning: **Trouble Shooting:** If the `sudoers` file becomes damaged, it could stop you from using `sudo` at all. To troubleshoot this, follow the thread here: [Ask Ubuntu: How to modify an invalid etc sudoers file](https://askubuntu.com/questions/73864/how-to-modify-an-invalid-etc-sudoers-file)

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
