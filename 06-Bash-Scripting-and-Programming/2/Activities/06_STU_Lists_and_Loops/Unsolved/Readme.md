## Activity File: Lists and Loops

In the previous activity we added variables to our script.  We also added conditional flow control using `if` statements.

Next, you will use loops to automate repetitive tasks in your script.

Loops facilitate code reuse, by allowing commands to be run many times without actually typing them repeatedly.

This adds another layer of sophistication and efficiency to your script.

To complete this activity, you will create several `for` loops that satisfy given requirements. If you get to the bonus, you can incorporate a `for` loop into your script.

### Create your script file.

1. Create a new file named `for_loops.sh` and open it in your text editor.

2. Add the required `boiler plate` line at the top so your computer knows it's a bash script.

### Create your variables

Create a variable that holds a list of 5 of your favorite U.S. states (e.g. Nebraska, Hawaii, California, etc.)

### Create a `for` loop

Create a `for` loop that checks for the state 'Hawaii' in your list of states. If the 'Hawaii' is there, print "Hawaii is the best!". If is not there, print "I'm not fond of Hawaii".

### Bonuses
1. Create a variable that holds a list of numbers from `0-9`. Then, create a `for` loop that prints out only the numbers 3, 5 and 7 from your list of numbers.

2. Create another variable that holds the output of the command `ls`. Then, create a `for` loop that prints out each item of this variable.


### Super Bonus

1. During the last exercise, you created a variable that holds the command `find /home -type f -perm 777 2> /dev/null` and then you used `echo` to print out your variable later in the script.

You may have noticed that this produces an output that is a bit jumbled together:

```bash
Exec Files:
/home/sysadmin/Documents/setup_scripts/sysadmin/day3_stu_setup.sh /home/instructor/Documents/setup_scripts/sysadmin/day3_stu_setup.sh /home/instructor/Documents/setup_scripts/instructor/day3_setup.sh
```

#### Challenge

Instead of using `echo` to print out this variable, use a `for` loop to print out each file on it's own line.
