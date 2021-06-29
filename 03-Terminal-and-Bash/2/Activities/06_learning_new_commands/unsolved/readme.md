## Activity File: Learning New Commands

- In this activity, you will continue your role as a security analyst at Wonka Corp. 

- Wonka Corp has recently experienced a network attack on their websites. They need your help determining which Wonka website was the main target of the attack.

- Your manager provided you with log files for each of Wonka Corp's websites. 

- Each log file contains the IP addresses that were connecting to that website on the day of the attack.

- You are tasked with counting the IP addresses in each file to determine which Wonka website was the main target of the attack.


### Instructions

Using only the command line, complete the following tasks from within the `/03-student/day2/learning_new_commands/` folder in your Ubuntu VM:
  
  1.  Within this directory are log files for each website. Within each log file is a list of IP addresses.  
      - Each line represents an hour.
      - Each line includes the IP addresses connecting to the website during that hour.

       Using manpages, research how to use the `wc` command to count the total number of IP addresses in each file.

      **Hint:** There is more than one IP address on each line, so the line count command will not work.

  2.  Run the command to determine which website had the most network connections and was therefore the likely target of the attack. 
  
#### Bonus
  
-  Use redirection with the new command to place the number of total IP addresses for each file into a file called `Connections_by_website`.

    **Hint:** Use a wildcard, such as `*`, to run this with a single command.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
