## Week 4 Homework Submission File: Linux Systems Administration

### Step 1: Ensure/Double Check Permissions on Sensitive Files

1. Permissions on `/etc/shadow` should allow only `root` read and write access.

    - Command to inspect permissions: ls -l /etc/shadow

    - Command to set permissions (if needed): sudo chmod u=rw,g=--,o=-- shadow

2. Permissions on `/etc/gshadow` should allow only `root` read and write access.

    - Command to inspect permissions: ls -l /etc/gshadow

    - Command to set permissions (if needed): sudo chmod u=rw,g=--,o=-- gshadow

3. Permissions on `/etc/group` should allow `root` read and write access, and allow everyone else read access only.

    - Command to inspect permissions: ls -l /etc/group

    - Command to set permissions (if needed): not needed

4. Permissions on `/etc/passwd` should allow `root` read and write access, and allow everyone else read access only.

    - Command to inspect permissions: ls -l /etc/passwd

    - Command to set permissions (if needed): not needed

### Step 2: Create User Accounts

1. Add user accounts for `sam`, `joe`, `amy`, `sara`, and `admin`.

    - Command to add each user account (include all five users): sudo adduser <username>

2. Ensure that only the `admin` has general sudo access.

    - Command to add `admin` to the `sudo` group: sudo usermod -aG sudo admin
    It could also be done through sudo visudo

### Step 3: Create User Group and Collaborative Folder

1. Add an `engineers` group to the system.

    - Command to add group: sudo addgroup engineers

2. Add users `sam`, `joe`, `amy`, and `sara` to the managed group.

    - Command to add users to `engineers` group (include all four users): sudo usermod -aG engineers <username>

3. Create a shared folder for this group at `/home/engineers`.

    - Command to create the shared folder: sudo mkdir /home/engineers

4. Change ownership on the new engineers' shared folder to the `engineers` group.

    - Command to change ownership of engineer's shared folder to engineer group: sudo chown root:engineers engineers

### Step 4: Lynis Auditing

1. Command to install Lynis: sudo apt -y install lynis

2. Command to see documentation and instructions: sudo lynis
sudo adduser --system --no-create-home --group lynis

3. Command to run an audit: sudo cat /etc/sudoers

4. Provide a report from the Lynis output on what can be done to harden the system.

    - Screenshot of report output: Run: sudo visudo
    Then add lynis ALL= NOPASSWD: /usr/sbin/lynis
    Then we change permission of the lynis to allow only the owner to execute it. We do this by first run: which lynis to locate the lynis package.Run sudo chmod 700 /usr/sbin/tripwire
    Run ls -l /usr/sbin/tripwire to verify.


### Bonus
1. Command to install chkrootkit: sudo apt -y install chkrootkit

2. Command to see documentation and instructions: sudo adduser --system --no-create-home --group chkrootkit

3. Command to run expert mode: tail /etc/passwd

4. Provide a report from the chrootkit output on what can be done to harden the system.
    - Screenshot of end of sample output: First we Run: sudo visudo
    Then add chkrootkit ALL= NOPASSWD: /usr/sbin/chkrootkit

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
