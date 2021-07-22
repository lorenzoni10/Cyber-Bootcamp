## Activity File: Compound Commands

In the previous Linux classes you learned a lot of different commands, which you typically execute one at a time. Now we can start combining commands together to save us time when working on the command line.

In this activity, you are working on auditing a new system and would like to simplify your job with automation. You will begin by combining several commands together to make fewer overall commands.

This exercise will give you an opportunity to explore creating some useful commands that combine several steps from the system audit we did on Linux Day 1.


Consider the following when completing this activity: 

  - Start by making sure that each command works on its own.

  - Add just one command at a time, ensuring that the entire line runs as you expect before adding more commands.

  - If you are unable to complete the command even with `sudo`, become the `root` user and run it again. 


Reminders of common programs you can chain together:

- `head` prints only the first 10 lines of output.
- `tail` prints only the last 10 lines of output.
- `sort` sorts the output alphabetically.
- `sed`  searches and replaces parts of the output.
- `awk`  displays only specified parts of the output.

#### Instructions

1. Create a research directory and copy all system logs along with the `shadow`, `passwd`, and `hosts` files in one long command.

2. Create a list of all executable files in the home folder and save it to a text file in the research folder with one long command.

3. Create a list of the 10 most active processes. The list should only contain the `USER`, `PID`, `%CPU`, `%MEM` and `COMMAND`. Save this list to a text file in your research directory with one long command.

#### Bonus

- Create a list of home folders along with user info from the `passwd` file. Only add the user info to your list if the `UID` is greater than 1000.


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    