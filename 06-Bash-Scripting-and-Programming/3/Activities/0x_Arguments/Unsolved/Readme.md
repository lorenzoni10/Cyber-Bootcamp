# Student Activity File - Bash Script Arguments

## Welcome!

In this warm-up activity, you will modify your last bash script to use a command line argument and a `HERE` doc.

Many times your scripts will want to take an action on some file or text that you provide it when you run the script, and often times you will want to write a lot of output to a file.

In this case, we want our system setup script to be able to write to a file that you specify when you run the script.

We will also check to see if that file was provided when the script was run and we will use a `HERE` doc to write to our ~/.bashrc file.

## Instructions

- Take your finished script from the code along in the last class.

- Write an _if_ statement at the beginning of the script that checks the variable for the first argument. If the variable is empty, exit the script.

- Replace all occurrences of your `$log_file` variable with the variable that represents the first argument given to the script.

- Check your script for any other opportunities to use variables to clean things up.

- Replace your bashrc aliases section with a `HERE` doc.

- Run your script and provide an output file as the first argument.