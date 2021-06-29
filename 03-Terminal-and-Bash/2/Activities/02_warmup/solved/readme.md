## Solution Guide: Warm-Up

- The first step is to navigate into the `/03-student/day2/warmup/` folder on your VM. To do this, run the following command:

    - `cd /03-student/day2/warmup/`
- Next,  confirm which directories are in this folder by running `ls`. This will display the following three directories:

    -  `physical_access_logs/`
    -  `server_logs/  `
    -  `web_logs/`
      
- The next step is to create a directory called `additional_evidence`. Run the following command:      

    - `mkdir additional_evidence`

- We have been tasked with viewing the `physical_access_logs`. To navigate into this directory, run:

    - `cd physical_access_logs/`
      
- Within this folder are six physical access logs. To view the contents, run preview commands (`head`, `more` or `less`) to find out which contain the data for October 13th. For example:

    - `head physical1`
       
 - After viewing all of the files, we determine that the two files containing logs for October 13th are `physical4` and `physical5`. We need to combine these two files into a single file called `Physical_Access_evidence`.
 
   To do this, run the `cat` command:  
 
   - `cat physical4  physical5 > Physical_Access_evidence`
 
 - We can run the `ls` command again to show that the file has been created.
 
 - Lastly, we need to move this new file over to the `additional_evidence` folder. We will do this using absolute paths:
 
    - `mv /03-student/day2/warmup/physical_access_logs/Physical_Access_evidence /03-student/day2/warmup/`
            
        

--- 

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
