## Solution Guide: Using awk

- The first step is to navigate into the `awk_activity directory`. To do this, run the following commands:
 
  - `cd /03-student/day3/`
  - `cd awk_activity`

- Move `Update1_Combined_Access_logs.txt` into the directory `/student_day3/learning_awk`:
     
   - `mv /03-student/day3/learning_sed/Update1_Combined_Access_logs.txt .`

      -  the  `.` will place the file in your current directory.
    
- Next we will write an `awk` command to isolate out the fields for time and username from this file.

  Open the file to see how the fields are separated and the field numbers for time and username. Run: 
    - `cat Update1_Combined_Access_logs.txt`
     
  - The fields are separated by spaces. Time is in field four, and username is in field six.

- To isolate those fields, we will run the following:

  - `awk '{print $4, $6}' Update1_Combined_Access_logs.txt`

- Lastly, we need to place these results into a file called `Update2_Combined_Access_logs.txt`:

  - `awk '{print $4, $6}' Update1_Combined_Access_logs.txt > Update2_Combined_Access_logs.txt`

- We can now open the new file using a preview command:

  - `more Update2_Combined_Access_logs.txt`

We can clearly see that the user  `MikeJones` is the primary user with the most bad logins.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


