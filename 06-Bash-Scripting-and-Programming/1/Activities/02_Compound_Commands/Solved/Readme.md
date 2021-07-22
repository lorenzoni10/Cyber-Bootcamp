## Solution Guide: Compound Commands

Completing this activity required the following steps:

- Creating a directory and automatically copying log files to it with one command.

- Finding a list of executable files in the home folder and saving it to a text file inside your directory with one command.

- Saving an edited list of the 10 most active processes to your directory with one command.

- Creating a list of home folders and users with a UID less than 1000 and saving it to your directory, all with one command.

---

Log into the lab environment with the username `sysadmin` and password `cybersecurity`.

Create a research directory and copy all system logs as well as the `shadow`, `passwd`, and `hosts` files in one long command.

- Run `mkdir ~/research && cp -r /var/log/* /etc/passwd /etc/shadow /etc/hosts ~/research`

We'll use `&&` to combine the two following commands together:

- `mkdir` to make our directory.

- `cp` to copy our files to our new directory.

- We also need to use `sudo` because we are making copies of sensitive `/etc` files.

Type the solution into the command line:

- `mkdir ~/research && sudo cp -r /var/log/* /etc/passwd /etc/shadow /etc/hosts ~/research`

Syntax breakdown:

- `mkdir ~/research`: Creates our directory.
- `&&`: Completes the second command if the first command is successful.
- `sudo cp -r /var/log/* /etc/passwd /etc/shadow /etc/hosts`: Chains together a number of files—as many as we want—to copy (recursively). 
- `~/research`: Output directory that we created with the first command.

Remember the command we discussed at the beginning of class: `file $(find / -iname *.txt 2>/dev/null) > ~/Desktop/text_files ; tail ~/Desktop/text_files`

- This command is an example in which `&&` might be better to use than `;` before we issue the `tail` command. This way, the file is completely written before we open it.

Create a list of all `exec` files and save it to a text file in the research folder using one long command.

- Run `sudo find /home -type f -perm 777 > ~/research/exec_lst.txt`

 This task only requires using one command, along with an output redirect to direct the list into a file that we specify. Again, we need to use `sudo` to search the entire system.

- Run `sudo find /home -type f -perm 777 > ~/research/exec_lst.txt`

   Syntax breakdown:

   - `sudo find` searches the entire directory.
   - `/` starts our search in the `root` directory.
   - `-type f` searches for objects that are files (not directories).
   - `-perm 777` searches for objects that have the `4000` bit set, or the `exec` bit.
   - ` > ~/research/exec_lst.txt` redirects the list returned by `find` to a text file.

Navigate to `/home/sysadmin/research`.

- Run `cat exec_lst.txt`

- Even though the last command gave us errors, our script told us it was ignoring those errors and continuing to read the other files that it did have access to. 


Create a list of the 10 most active processes. The list should only contain the `USER`, `PID`, `%CPU`, `%MEM` and `COMMAND`. Save this list to a text file in your research directory with  long command.

- Run: `ps aux --sort -%mem | awk {'print $1, $2, $3, $4, $11'} | head > ~/research/top_processes.txt`

Parsing the output of the `ps` command will require using a program like `awk`.

   - Run `ps aux --sort -%mem`

   - The `--sort` flag allows us to sort the `ps` output by various criteria. In this case, we are using `-%mem` to sort by memory.

   Add the `awk` command: `ps aux --sort -%mem | awk {'print $1, $2, $3, $4, $11'}`

   - Syntax breakdown:

      - `awk` allows us to parse the output to make it more readable.
      - `{'print` is an argument for `awk` indicating that we want to print what comes next.
      - `$1, $2, $3, $4, $11'}`: Each item on a line, separated by white space, that is given to `awk` is given a number. We can later choose those items using the `$`. Here, we are choosing `USER`, `PID`, `%CPU`, `%MEM` and `COMMAND`.

Add the `head` and output parts of the command:
`ps aux --sort -%mem | awk {'print $1, $2, $3, $4, $11'} | head > ~/research/top_processes.txt`

- We are using `head` to give us only the first ten lines, before we send the command to our research directory.

#### Bonus

Create a list of home folders along with user info from the `passwd` file. Only add the user info to your list if the UID is greater than 1000.

   - Run: `ls /home > ~/research/users.txt && cat /etc/passwd | awk -F ":" '{if ($3 >= 1000) print $0}' >> ~/research/users.txt`


- We will again need to use `awk` to parse the output of the `passwd` file.

- Type the first part of the command: `ls /home > ~/research/users.txt &&`

   - This command creates a list of the home folders and saves it. Then, we are using the `&&` to make sure that this command completes before we add more to that file.

Type out the next part of the command: `cat /etc/passwd | awk -F ":" '{if ($3 >= 1000) print $0}'`

- `cat /etc/passwd` gives us the entire contents of the `passwd` file.
- `|` sends those contents to our next command.
- `awk` allows us to parse the output.
- `-F ":"` changes the delimiter that `awk` is using to parse input. By default, `awk` uses white space to divide lines of text, but here we are changing it to a colon because items are separated by a colon in the `passwd` file.
- `'{if ($3 >= 1000) print $0}'` This is an `if` statement inside of `awk`. It says, if the third item given is greater than 1000, print `$0`, which is the entire line.
   - Remember that `awk` assigns each item a number and the number `0` is assigned to the entire line. 
   
Run the entire command: `ls /home > ~/research/users.txt && cat /etc/passwd | awk -F ":" '{if ($3 >= 1000) print $0}' >> ~/research/users.txt`


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
