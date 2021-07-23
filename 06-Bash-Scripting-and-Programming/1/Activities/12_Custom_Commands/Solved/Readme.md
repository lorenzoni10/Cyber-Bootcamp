## Solution Guide: Custom Commands

This activity turned our script into a custom command and added a script directory to the `$PATH` so that command can be called directly.

To complete this activity, we needed to do the following:

- Ensure that the script from the last activity runs as expected.
- Add the new commands listed in the instructions.
- Save the script in a ~/scripts directory.
- Add that ~/scripts directory to the `$PATH` variable.
- Run your script by calling it's name only.


### Solutions

Inside your script, add the command for creating a `~/research` directory to your script.

- `mkdir ~/research 2> /dev/null`
    ```bash
    # Create directory for output
    mkdir ~/research 2> /dev/null
    ```

Add the command used to find `777` files to your script.

- `echo -e "\n777 Files:" >> ~/research/sys_info.txt`

- `find / -type f -perm 777 >> ~/research/sys_info.txt`

These next two commands are exactly the same as they were in first two exercises. The only thing we are adding is an `echo` command that will give each command's output a heading.

Add the command for finding the top 10 processes to your script.

- `echo -e "\nTop 10 Processes" >> ~/research/sys_info.txt`
- `ps aux -m | awk {'print $1, $2, $3, $4, $11'} | head >> ~/research/sys_info.txt`

Modify each command of the script so that it writes all output to a file called `~/research/sys_info.txt`

- Add `>> ~/research/sys_info.txt` to each line of your script.

At this point, our script should resemble the following. (Note: Script may vary if the bonus was completed in the last activity.)

```bash
#!/bin/bash

mkdir ~/research 2> /dev/null

echo "A Quick System Audit Script" >  ~/research/sys_info.txt
date >> ~/research/sys_info.txt
echo "" >> ~/research/sys_info.txt
echo "Machine Type Info:" >> ~/research/sys_info.txt
echo $MACHTYPE >> ~/research/sys_info.txt
echo -e "Uname info: $(uname -a) \n" >> ~/research/sys_info.txt
echo -e "IP Info: $(ip addr | grep inet | tail -2 | head -1) \n" >> ~/research/sys_info.txt
echo "Hostname: $(hostname -s) " >> ~/research/sys_info.txt
echo -e "\n777 Files:" >>  ~/research/sys_info.txt
find / -type f -perm 777 >> ~/research/sys_info.txt
echo -e "\nTop 10 Processes" >> ~/research/sys_info.txt
ps aux -m | awk {'print $1, $2, $3, $4, $11'} | head >> ~/research/sys_info.txt

```

#### Bonus Additions

In your command line environment, manually create a `~/scripts` directory and save your script there. (This is a great opportunity to chain two commands together to complete a task.)

- `mkdir ~/scripts && cp sys_info.sh ~/scripts`

Add your `~/scripts` directory to your `$PATH`

- `echo "export PATH=$PATH:~/scripts" >> ~/.bashrc`

    - `echo` is printing everything that comes next.
    - `"export` allows the variable to be used across different shells.
    - `PATH=` is the assignment of our variable.
    - `$PATH` is calling the variable as it is now. So, the first part of our new variable for `PATH` will be a copy of the old variable `PATH`.
    - `:` is the delimiter used within the `PATH` variable in between each directory path.
    - `~/scripts"` is the directory we are adding and closes out the `echo` command.
    - `>> ~/.bashrc` appends the output from `echo` to the bottom of the `bashrc` file.

Run `tail -1 bashrc`.

- Your output should be similar to:

    ```bash
    $ tail -1 ~/.bashrc
    PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/snap/bin:/usr/local/lib/python3.7/site-packages/:/home/user/.local/bin:/home/user/scripts
    ```

Reload your bashrc file.

-  `source ~/.bashrc`

    Note: we only need to type the name of the script file in order to run it.

Run your script:

-  `sys_info.sh`

    Futhermore: we can remove the `.sh` file extension to make this more like a command.

We now have a command `sin` that runs all the commands in your script and saves them to an output file.

- Run `mv ~/scripts/sys_info.sh ~/scripts/sin`

Open `~/research/sys_info.txt` and verify it has the desired output.

- Run `less ~/research/sys_info.txt`


The contents of `sys_info.txt` file should look similar to the following. (Results will vary.)

```
A Quick System Audit Script
Mon Aug 17 10:46:07 EDT 2020

Machine Type Info:
x86_64-pc-linux-gnu
Uname info: Linux ubuntu-vm 4.15.0-70-generic #79-Ubuntu SMP Tue Nov 12 10:36:11
 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux 

IP Info:     inet6 fe80::4fd8:a255:a4b4:8045/64 scope link noprefixroute 

Hostname: ubuntu-vm 

777 Files:
/home/sysadmin/script.sh
/home/sysadmin/research/myscript.sh
/splunk/splunk.sh
/splunk/logs/Week-1-Day-3-Logs/statsreport.csv

Top 10 Processes
USER PID %CPU %MEM COMMAND
root 1 0.0 0.2 /sbin/init
root - 0.0 - -
root 2 0.0 0.0 [kthreadd]
root - 0.0 - -
root 4 0.0 0.0 [kworker/0:0H]
root - 0.0 - -
root 5 0.0 0.0 [kworker/u4:0]
root - 0.0 - -
root 6 0.0 0.0 [mm_percpu_wq]
```

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    