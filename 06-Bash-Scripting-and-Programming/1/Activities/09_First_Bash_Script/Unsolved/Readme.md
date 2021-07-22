## Activity File: My First Bash Script

- In the previous activity you created several aliases and saved them to your `~/.bashrc` file. You may have noticed that creating long strings of commands can get a bit cumbersome when working on the command line.

- Now, we will put our commands into a script file. Reading, writing, and running Bash scripts are a staple of any good sysadmin.

- In this activity, you will create a script that completes several system audit steps automatically.

When completing this activity, consider the following:

- Start by ensuring each command will give you the expected output before adding it to your script.

- Some commands may not have been covered and require additional research.
- Add all the commands listed in the instructions to your script.
- Ensure the output of each command has a title like: `The Memory Info is:`
- Change the permissions on your script to make it executable.
- Run your script to verify it produces the correct output.

As a reminder, here are a few helpful environment and shell variables:

- `USER`
- `HOME`
- `SHELL`
- `PWD`
- `BASH`
- `HOSTNAME`
- `MACHTYPE`
- `UID`


### Instructions

Complete the following set-up:

- Create a new script file called `sys_info.sh`.

- Change the permissions on the file to make it executable.

- Open the file with `nano`.

- Add a top `hashbang` line to make this a bash script.

Your script should output the following data:

- A title and today's date.

- The `uname` info for the machine.

- The machine's IP address. (Narrow this output down to one line.)

- The Hostname.

Run your script using `./` notation.

#### Bonus Script Ideas

If you complete the script above, try adding a few of these items:

- The DNS info.

- The Memory info.

- The CPU info.

- The Disk usage.

- The currently logged on users.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    