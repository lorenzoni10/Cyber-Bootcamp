## Activity File: Users and Groups

In our previous activity, we tightened `sudo` access across the system by editing the `sudoers` file. The administrator has asked that we audit all the users and groups on the system, create a new group for the standard users, and remove users from the `sudo` group. In our previous activities we found some malicious users, and we will want to remove them from the system altogether.

 We want to follow the principle of least privilege to make sure that users on the system only have the correct access. Despite the changes we have made so far, there are still unauthorized users in groups who have access to sensitive data.

 Your senior systems administrator has asked you to audit these groups and remove both unauthorized users as well as suspicious groups.

To complete these tasks, your senior administrator has asked that you do the following:

- Check every user's UID and GID.

- Make sure that only the sysadmin account is in the `sudoers` group.
- If you find a user that is part of the `sudoers` group, remove them from that group and document your findings.
- Remove any users from the system that should not be there.
- Verify that all non-admin users are part of the group `developers`. If the `developers` group doesn't exist, create it and add the users. We can use this group later to configure file sharing among these users.
- The users `adam`, `billy`, `sally`, and `max` should only be members of the `developers` group and their own ("primary") groups. If you find any groups other than this, document the group and remove it.

This activity will use the same lab environment that you have been using for the previous activities.

- Username: `sysadmin`   
- Password: `cybersecurity`

### Instructions

Begin in the command line inside your lab environment.

1. Use a command to display your ID info.

2. Use the same command to display the ID info for each user on the system.
    - In case you forgot, how can you learn what these usernames are?
    - Record the output from this series of commands to a new file in your research folder.

3. Print the groups that you and the other users belong to.
    - Record the output from this series of commands to a new file in your research folder.

4. Document in your research folder anything suspicious related to any of the users.
    - Hint: Are there any users that shouldn't be there?

5. Make sure you have a copy of the home folder for any rogue users and then remove any users from the system that should not be there. Make sure to remove their home folders as well.  

   _**Hint:** Remember from the first activity, the only standard users that should be on the system are: `admin`, `adam`, `billy`, `sally` and `max`._

6. Verify that all non-admin users are part of the group `developers`.
    - If the `developers` group doesn't exist, create it and add the users.

7. The users `adam`, `billy`, `sally` and `max` should _only_ be members of the `developers` group and their own groups. If you find any groups other than this, document and remove it.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
