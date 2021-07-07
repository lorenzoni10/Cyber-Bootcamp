## Solution Guide: Users and Groups

1. Display your UID, GID, and other permissions info.
    - Run: `id`

2. Use the same command to display the UID, GID, and permissions info for each user on the system.
    - You can learn what these usernames are by running `id <username>`.

- Record the output from this series of commands to a new file in your research folder.

    - Run: `id <username> >> ~/research/user_ids.txt`

3. Print the groups you and the other users belong to.

    - Run: `groups <username>`

- Record the output from this series of commands to a new file in your research folder.

    - Run: `groups <username> >> ~/research/user_groups.txt`

4. Document in your research folder anything suspicious related to any of the users.

    - You should find that the user `jack` is part of the `sudo` group.

    - To remove them from the sudo group, run `sudo usermod -G jack jack`.

- Remove any users from the system that should not be there.

    - Run: `sudo deluser --remove-home jack`

6. Verify that all non-admin users are part of the group `developers`. If the `developers` group doesn't exist, create it and add the users.

    - Run: `sudo addgroup developers` and `sudo usermod -G developers <username>`

7. The users `adam`, `billy`, `sally` and `max` should only be members of the `developers` group and their own groups. If you find any groups other than this, document the group and remove it.

    - Run: `sudo delgroup hax0rs`


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
