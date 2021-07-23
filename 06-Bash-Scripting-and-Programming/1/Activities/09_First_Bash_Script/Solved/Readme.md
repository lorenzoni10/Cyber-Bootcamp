## Solutions Guide: First Bash Script

To complete this activity, you needed to do the following:

- Add all the commands in the instructions to your script. 
- Change the permissions on your script to make it executable.
- Run your script to verify it produces the correct output.

### Solutions

Create a new script file.

- `touch sys_info.sh`

Change the permissions on the file to make it executable.

- `chmod +x sys_info.sh`

Open the file with `nano`.

- `nano sys_info.sh`

Add a top `hashbang` line to make this a bash script.

- `#!/bin/bash`


At this point your terminal output should look like:

```bash
touch sys_info.sh
chmod +x sys_info.sh
nano sys_info.sh  
```

Then inside nano, you should have:

```bash
#!/bin/bash
```

#### Add the following to your script:

A title.

- `echo "A Quick System Audit Script"`

Today's date.
-  `date`

The machine's type.
- `echo "Machine Type Info:"`
- `echo $MACHTYPE`

  - `echo`:expands any input it's given before sending it to the output.
  - `$MACHTYPE` is a 'built-in' variable that contains the type of machine you are working on.


The `uname` info for the machine.

-  `echo -e "Uname info: $(uname -a) \n"`'

  - `echo` sends everything to output.
  - `-e` enables `echo` to read added line breaks within the line to be echoed.
  - `"Uname info: ` is printed out as shown.
  - `$(uname -a)` is run before any other part of the line is run. This part gets run **first**. Then, it's output is added to the line and the rest of the echo command is run.
  - `\n"` closes out the `echo` command and adds a line break. **Note**: this only works because we are adding the `-e` flag to `echo`.


The machine's IP address.

-  `echo -e "IP Info: $(ip addr | head -9 | tail -1) \n"`


Let's breakdown this line:

`ip addr` is expanded. 

- Run `ip addr`.

Your output should look similar to:

  ```bash
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
        valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host
        valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
      link/ether 00:16:3e:5e:6c:00 brd ff:ff:ff:ff:ff:ff
      inet 10.137.0.21/32 brd 10.255.255.255 scope global eth0
        valid_lft forever preferred_lft forever
      inet6 fe80::216:3eff:fe5e:6c00/64 scope link
        valid_lft forever preferred_lft forever
  ```

We want to narrow this output down to the line that contains our main IP address. In this case it is the ninth. 

- Run `ip addr | head -9`.

  Your output should be:

    ```bash
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
          valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host
          valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
        link/ether 00:16:3e:5e:6c:00 brd ff:ff:ff:ff:ff:ff
        inet 10.137.0.21/32 brd 10.255.255.255 scope global eth0
    ```

Use `tail` to get the last line.

- Run `ip addr | head -9 | tail -1`

  Your output should be:

    ```bash
    inet 10.137.0.21/32 brd 10.255.255.255 scope global eth0
    ```

Now, surround this command with our expansion syntax `$()` so it runs before `echo`:

- Run: `echo -e "IP Info: $(ip addr | head -9 | tail -1) \n"`

  Your output should be similar to:

  ```bash
  IP Info:     inet 10.137.0.21/32 brd 10.255.255.255 scope global eth0

  ```

Let's return to the script.

The Hostname.

- `echo "Hostname: $(hostname -s) "`

  - The `-s` flag for hostname provides a 'short' hostname and is not absolutely required.

The final script should be similar to:

```bash
#!/bin/bash

echo "A Quick System Audit Script"
date
echo ""
echo "Machine Type Info:"
echo $MACHTYPE
echo -e "Uname info: $(uname -a) \n"
echo -e "IP Info: $(ip addr | grep inet | tail -2 | head -1) \n"
echo "Hostname: $(hostname -s) "
```

#### Bonuses:

The DNS info.

  - `echo "DNS Servers: "`

  - `cat /etc/resolv.conf`

    The `DNS` info is stored in the `/etc/resolv.conf` file. All we need to do is display the contents of this file using `cat`.

The Memory info.

  - `echo "Memory Info:"`

  - `free`

The CPU info.

  - `echo -e "\nCPU Info:"`

    -  `echo -e "\nCPU Info:"` gives us a title with a line break before it.


  - `lscpu | grep CPU`

    - `lscpu` gives us a ton of info about the computer's CPU.
    - Remember: `ls` has a number of extended commands to show hardware and other system info. 
    - `| grep` pipes that output into `grep` so we can parse just the info we want.
    - `CPU` is given to `grep` to display lines that only contain `CPU`.



The Disk usage.
- `echo -e "\nDisk Usage:"`
- `df -H | head -2`
    - `df` retrieves the disk information.
    - `-H` displays the info in `human readable` format. This means it will display bytes in `megabytes` an `gigabytes` instead of `bytes`.
    - `| head`: Again, we are piping the command into the `head` command to limit output.
    - `2` limits the output of `head` to 2 lines.


The currently logged on users.

- `echo -e "\nWho is logged in: \n $(who -a) \n"`

  - `echo -e "\n` initiates our `echo` command and creates a line break.
  - `Who is logged in: \n` will be printed as shown with another line break.
  - `$(who)` runs the `who` command before the `echo` command.
  - ` \n` provides another line break.

At this point, our script should look like:

```bash
#!/bin/bash

echo "A Quick System Audit Script"
date
echo ""
echo "Machine Type Info:"
echo $MACHTYPE
echo -e "Uname info: $(uname -a) \n"
echo -e "IP Info: $(ip addr | grep inet | tail -2 | head -1) \n"
echo "Hostname: $(hostname -s) "
echo "DNS Servers: "
cat /etc/resolv.conf
echo "Memory Info:"
free
echo -e "\nCPU Info:"
lscpu | grep CPU
echo -e "\nDisk Usage:"
df -H | head -2
echo -e "\nWho is logged in: \n $(who) \n"
```

Close and save your script file.


Run your script using `./` notation.

- `./sys_info.sh`

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    