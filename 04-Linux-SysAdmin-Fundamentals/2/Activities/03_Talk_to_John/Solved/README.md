## Solution Guide: Let's Talk to John

In this activity, you used the program `john the ripper` to crack the passwords for several users on the system. 

### Solutions

1. Make a copy of the /etc/shadow file in your /home/sysadmin directory.  Name the copy: "shadow_copy"

    - `cd /home/sysadmin`
    - `sudo cp /etc/shadow shadow_copy`
  
2. Use Nano to edit your "shadow_copy" file to leave only the rows for the following users you will crack: Jack, Adam, Billy, Sally, Max
      
    - Run `sudo nano shadow_copy` and delete all extra lines that are not the above users.
    
    - Note: `ctrl-k` will delete the current line in Nano.

    - Your edited file should be similar to this:

      ```bash
      max:$6$WhPNYTYJx2jx25x$QWy.....     
      billy:$6$Q.zRCddM9cwb5YUJh......
      jack:$6$ilIqVoXkja6GG8PK$t....
      ```
            
3. Run `sudo john shadow_copy`.

4. This will take some time, but let John the Ripper run, and take note of any passwords you find. 
   
   - You should be able to crack the following passwords fairly quickly:

      - `jack` : lakers
      - `adam` : welcome
      - `billy`: football
      - `sally` : 123456
      - `max` : welcome

Note:  Since we use `sudo cp /etc/shadow shadow_copy`, shadow_copy will be owned by root, and have the same permissions as the original.  
Therefore, we have to use `sudo nano` and `sudo john`.  Alternatively, we could have changed the ownership of shadow_copy with `sudo chown sysadmin:sysadmin shadow_copy`, and then not have to use sudo for nano or john.

—--

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
