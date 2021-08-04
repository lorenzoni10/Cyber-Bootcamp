## Solution Guide: Move and Create Directories

In this activity, you were tasked with setting up multiple directories for the Windows workstation.

---

1. Since we will eventually decommission the `Alex` user, move the `contracts` folder from Alex's desktop directory to `C:\`.


  - First, make sure we're working out of Alex's desktop directory:

    - Run `Set-Location C:\Users\Alex\Desktop` to change directory.

    - This is the same as `cd` in Linux.

  - Next, move `contracts` to `C:\`:

    - Run `Move-Item contracts C:\` to move the `contracts` directory to the `C:\` directory.

    - This is the same as `mv` in Linux.

  - Verify `contracts` is no longer here:

    - Run `Get-ChildItem C:\` to get a listing of the directories and files in `C:\`.

    - This is the same as `ls` in Linux.


2. Create `Backups` and `Scripts` directories in `C:\`.


  - Now, we want to work out of `C:\`.

  - Run `Set-Location C:\`.

  - Make the `Backups`, `Logs`, and `Scripts` directories:

    - Type `New-Item -Path "C:\" -Name "Logs" -ItemType "Directory"`, but don't run it yet.

    - When we use the `-ItemType "Directory"` parameters here, it changes the `New-Item` functionality from being like `touch` to `mkdir` in Linux.

  - We can actually shorten this command a little and have it create both directories:

    - Edit the line to match the following:

    - Run `New-Item "Logs", "Backups", "Scripts" -ItemType "Directory" -Force`

    - This command will create all the directories in the current directory.

    - This is similar to using _brace expansion_ with `mkdir`:  `mkdir {Logs, Backups, Scripts}`.

    - The `-Force` parameter will ignore any errors if the directories already exist.

3. Check the contents of the `C:\` directory to make sure the `Logs`, `Backups`, and `Scripts` directories exist.


  - Run `Get-ChildItem` to show `contracts`, `Logs`, `Backups`, and `Scripts` in `C:\`. We now have the following directories:

    - `C:\Backups`
    - `C:\Logs`
    - `C:\contracts`
    - `C:\Scripts`

**Bonus**

4. Use `Rename-Item` to capitalize the `contracts` directory if it is not already.


  - Use `Rename-Item` to capitalize the `contracts` directory. 

    - `Rename-Item contracts Contracts` seems like the correct option (if you recall `mv` in bash), but the command actually errors out. 

  - Instead, we use `Rename-Item` twice to change the directory name: 

    - `Rename-Item contracts contracts1`

    - `Rename-Item contracts1 Contracts`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
