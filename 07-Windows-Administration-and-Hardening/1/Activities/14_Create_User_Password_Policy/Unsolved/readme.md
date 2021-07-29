## Activity File: Creating Users and Setting Password Policies

In the previous activity, you used the `net` command-line tool to find various types of information.

- Your CIO noticed the previous password policies were not very strict, and wants to enforce new password policies on this Windows workstation for the next two new users: senior developer Andrew, and sales representative Bob.

- You are tasked with creating a regular user, `Bob`, and an administrative user, `Andrew`, and set the password policies with the following parameters:

  - Maximum password age is 90 days.

  - Minimum password length is 12 characters.

  - Password complexity requirements are enabled.

Continue using the Windows RDP Host machine. 

### Instructions

1. Create a regular user, `Bob`, using the `net user` command-line tool.

2. Set the user's password to `Ilovesales123!`. They will change this on their first day.
    - Note that you can use `net user [username] *` to change the password of an existing user (if you added the user without setting the password, or set it improperly). 

3. Create a user, `Andrew`, and add them to the `Administrators` group.

4. Set the user's password to `Ilovedevelopment123!`. They will change this on their first day.

5. Use `net` to verify that Andrew is in the `Administrators` group.

6. Launch `gpedit` and set the following password policies for the entire Windows machine:

    - Maximum password age is 90 days.

    - Minimum password length is 12 characters.

    - Password complexity requirements are enabled.

----

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
