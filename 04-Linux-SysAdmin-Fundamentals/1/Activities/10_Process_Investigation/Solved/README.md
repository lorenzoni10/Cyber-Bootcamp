## Solution Guide: Process Investigation

The goal of this activity was to identify resource draining services affecting our system. More specifically this activity required the following steps:

- Use `top` to monitor for suspicious processes.

- Use `ps` to check what processes are running.

- Identify a suspicious process.

- Research signal flags used with the `kill` command.

- Use the appropriate `kill` signal to stop the suspicious process.

---

1. During the last activity, you found a script file in a strange location on the system. Review the contents of this script file to get an idea of what commands you might be searching for.

    - List all the running processes in real time.
      - Solution: `top`

    - Review the help menu for this command and get a few ideas of what you want to investigate.
      - Solution: `man top`

    - Highlight the column that you are sorting by.
      - Solution: You can enable column highlighting and sorting by pressing the `x` key. By default, the `%CPU` column is highlighted and sorted by highest `CPU` usage.


2. To get an idea of how the system is currently running, answer these questions:

   **Note:** Answers will vary by machine. We'll use the following example image to answer these questions

   - How many tasks have been started on the host?
     - Solution: `250`
     
   - How many of these are sleeping?
     - Solution: `0`

   - Which process uses the most memory?
     - Solution: `gnome-shell`

![2](images/2.png)


3. Search all running processes for a specific user.

    - Review all the processes started by the `root` or `sysadmin` user.
      - Solution type: `u` followed by the name of the user. 

    - Sort by other users on the system that may be of interest.
  
     **Hint**: In the previous exercise, you found a home folder for a user who should not be on this system. Is that user running processes?
      - Solution: Jack is running the `stress-ng` processes
      
![3](images/3.png)

**Bonus**

4. Next, take a static "snapshot" of all currently running processes, and save it to a file in your home directory with the name `currently_running_processes`.

    - Use the flag to list all processes that have a TTY terminal.
      - Solution: `ps aux >> ~/currently_running_processes`

    - In the short list of output, do you notice any processes that appear suspicious?
      - Solution: Yes, Jack is running a process `stress0ng --matrix 0 --times`. These commands intentionally stress the system and consume resources which could result in a Denial of Service from the server.

![4](images/4.png)

5. Identify the ID of any suspicious process. Stop that process with the `kill` command.
    - Solution: Run `kill <PID number>` or `kill 4714 4715`.




6. `Kill` all processes launched by the user who started the command you just stopped. 

    - Use Google and the man pages to identify a command and flag that will let you stop all processes owned by a specific user.

  - Solution: `sudo killall -u jack`.


-------

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

