## Activity File: My First Shell Script   
  
- You continue in your role as a security analyst at Wonka Corp.

- Your manager needs your assistance creating a simple shell script to automate the `awk` and `sed` tasks you completed today on your log file.

- This shell script can be provided to other security analysts so they can easily complete the same tasks you ran today.

- You are tasked with using `nano` to create a shell script with the `awk` and `sed` commands to analyze a log file.

### Instructions

Using only the command line, complete the following tasks from within the `/03-student/day3/first_shell_script/` folder in your Ubuntu VM:
  
1. Within this directory is a log file to analyze called `LogA.txt`. Use `nano` to create a script called `Log_analysis.sh`.
2. Within this script, place the `sed` command and `awk` command used in the previous activities to analyze the `LogA.txt` file.
3. When using your `sed` command from the previous activity, send the results to a new file named `access_denied.txt`. 
4. When using your `awk` command from the previous activity, send the results to a new file named `filtered_logs.txt`. 
- Note: If you have not finished the previous activity, feel free to use the code snippet below, and update the file names where necessary:

      sed s/INCORRECT_PASSWORD/ACCESS_DENIED/ LogA.txt > FILL IN
      awk '{print $4, $6}' FILL IN > FILL IN

3. Run the command to confirm the commands run as expected.
    
--- 

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
