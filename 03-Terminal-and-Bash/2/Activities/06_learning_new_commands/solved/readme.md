## Solution Guide: Learning New Commands

- First, navigate into the `/03-student/day2/learning_new_commands` folder on your VM. To do this, run the following commands:
 
  - `cd /03-student/day2/learning_new_commands`    

- Next we will view the log files in this directory, by running `ls`.  

    - Notice that there are five files in this directory, one for each website:

        - `Chocolateyfun.com`  
        - `GummyGummy.com  `
        - `PeanutButtery.net`  
        - `Stickytoffee.com`  
        - `SugaryGoodness.com`

- Next we will preview the contents of the file to see the structure of the logs. Run the following: 

  - `head Chocolateyfun.com`

  - Notice that in each log file, each line represents an hour. And, each line shows the IP addresses that connected to the website during that hour.

- We don't want to use the `wc -l` command to count the lines. We need a command to count the total IP addresses in the file. Note that each IP is considered a word, as it is surrounded by spaces.

  We will view the man page for `wc` to see how to count each IP address. Run the following command:

  - `man wc`
    
  The man page shows that the option of `-w` will count the words.  This will be the best option for our task.

  - Enter `q` to exit the man page.

- Since we now know how to find the word count, we will run this on all the five files.

  - `wc -w Chocolateyfun.com`  
  - `wc -w GummyGummy.com`  
  - `wc -w PeanutButtery.net` 
  - `wc -w Stickytoffee.com`
  - `wc -w SugaryGoodness.com`

- The results will show that PeanutButtery.net has the highest count, and is likely the target of the attack.
  ```
  155 Chocolateyfun.com
  109 GummyGummy.com
  533 PeanutButtery.net
  129 Stickytoffee.com
  113 SugaryGoodness.com
  ```

- If you run `nano GummyGummy.com` you'll notice that there are extra spaces on the fourth and fourteenth lines. Thee `wc` command counts spaces as words, so the exact number of IP addresses is only as accurate as the file itself. 
     
**Bonus**    

- To run the word count command against all the files, you have to use a wildcard: `*`. (Wildcards will be covered in more detail in the next lesson.) The command will be :   
    
  - `wc -w *`
    
  - This will run the word count command for all the files in the current directory with a single command.

- If you want to redirect these results into the file `Connections_by_website`, the command is:   

  - `wc -w * > Connections_by_website`
    
- Lastly, preview the `Connections_by_website` file to confirm the results are now in this file:   

  - `head Connections_by_website`

--- 

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
