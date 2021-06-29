## Activity File: Using sed   
  
- You continue in your role as security analyst at Wonka Corp.

- Your manager believes there is a new cybercriminal trying, but failing, to log into several administrative websites owned by Wonka.

- Your manager wants to find out information about this cybercriminal before they get unauthorized access.

- Your manager has provided you with the access logs for two administrative websites.

- Your first task is to combine the two access logs into a single file, and then use text processing to make the "failed login" data consistent.

### Instructions

Using only the command line, complete the following tasks from within the `/03-student/day3/learning_sed` folder in your Ubuntu VM:
  
  1. Within this directory are two log files from different administrative websites. 
  
      - Combine the two log files into a single log file called `Combined_Access_logs.txt`.
      - Note: Use the file named `combined` to check your work. 

  2. Failed logins are titled as `ACCESS_DENIED` or `INCORRECT_PASSWORD`.

     - Using `sed`, replace all instances of `INCORRECT_PASSWORD` with `ACCESS_DENIED` so the data is consistent.

  3. Save the results to a new file called `Update1_Combined_Access_logs.txt`. 

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
