## Activity File: Let's Talk to John


In this activity, your senior administrator has asked you to audit the strength of users' passwords by using the `john` program and document any passwords that you find.

To complete these tasks, you will use the program `john the ripper` on the password file you viewed from Day 1. You will use `john` to crack the passwords for several users on the system. 

:warning: `john the ripper` should have been installed during the **Installing Packages** activity from the previous class. 

### Instructions

1. Make a copy of the /etc/shadow file in your /home/sysadmin directory.  Name the copy: "shadow_copy"

    - **Note**: Don't forget to use sudo!
  
2. Use nano to edit your "shadow_copy" file to leave only the rows for the following users to crack:
      - Jack, Adam, Billy, Sally, Max

3. Run `sudo john shadow_copy`
     - **Note**: This command is all you need to crack passwords.

4. This will take some time, but let John the Ripper run, and take note of any passwords you find.

—--

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


