## Solution Guide: Lists and Loops

In the previous activity we added variables to our script.  We also added conditional flow control using `if` statements.

Next, you will use loops to automate repetitive tasks in your script.

Loops facilitate code reuse, by allowing commands to be run many times without actually typing them repeatedly.

To complete this activity, you will create several `for` loops that satisfy given requirements. If you get to the bonus, you can incorporate a `for` loop into your script.

### Instructions

#### Create your script file.
1. Create a new file named `for_loops.sh` and open it in your text editor.
**Solution**: `nano for_loops.sh`

2. Add the required `boiler plate` line at the top so your computer knows it's a bash script.
**Solution**: `#!/bin/bash`

#### Create your variables

Create another variable that holds a list of 5 of your favorite U.S. states (e.g. Nebraska, Hawaii, California, etc.)
**Solution**: `states=('Nebraska' 'California' 'Texas' 'Hawaii' 'Washington')`
#### Create a `for` loop

Create a `for` loop that checks for the state 'Hawaii' in your list of states. If the 'Hawaii' is there, print "Hawaii is the best!". If is not there, print "I'm not fond of Hawaii".

**Solution**:
```bash
for state in ${states[@]}
do

  if [ $state == 'Hawaii' ];
  then
    echo "Hawaii is the best!"
  else
    echo "I'm not a fan of Hawaii."
  fi
done
```
### Bonuses

1. Create a variable that holds a list of numbers from `0-9`

    **Solution**: `nums=$(echo {0..9})`

    Then create a `for` loop that prints out only the numbers 3, 5 and 7 from your list of numbers.

    **Solution**:
    ```bash
    for num in ${nums[@]}
    do
      if [ $num = 3 ] || [ $num = 5 ] || [ $num = 7 ]
      then
        echo $num
      fi
    done
    ```

2. Create another variable that holds the output of the command `ls`

    **Solution**: `ls_out=$(ls)`

    Then create a `for` loop that prints out each item in your variable that holds the output of the `ls` command.

    **Solution**:
    ```bash
    for x in ${ls_out[@]}
    do
      echo $x
    done
    ```

#### Super Bonus

1. During the last exercise, you created a variable that holds the command `find / -type f -perm /4000 2> /dev/null` and then you used `echo` to print out your variable later in the script.

You may have noticed that this produces an output that is a bit jumbled together:
```bash
Exec Files:
/home/sysadmin/Documents/setup_scripts/sysadmin/day3_stu_setup.sh /home/instructor/Documents/setup_scripts/sysadmin/day3_stu_setup.sh /home/instructor/Documents/setup_scripts/instructor/day3_setup.sh

```

##### Challenge
Instead of using `echo` to print out this variable, use a `for` loop to print out each file on it's own line.
**Solution**:
```bash
execs=$(find /home -type f -perm 777 2> /dev/null)

for exec in ${execs[@]}
do
  echo $exec
done
```

### Example Contents of for_loops.sh
```bash
#!/bin/bash

# Create Variables
nums=$(seq 0 9)
states=('Nebraska' 'California' 'Texas' 'Hawaii' 'Washington' 'New York')
ls_out=$(ls)
execs=$(find /home -type f -perm 777 2> /dev/null)

# Create For Loops
# Create a loop that prints 3, 5, or 7
for num in ${nums[@]}
do
  if [ $num = 3 ] || [ $num = 5 ] || [ $num = 7 ]
  then
    echo $num
  fi
done


# Create a loop that looks for 'Hawaii'
for state in ${states[@]};
do
  if [ $state == 'Hawaii' ];

  then
    echo "Hawaii is the best!"
  else
    echo "I'm not a fan of Hawaii."
  fi
done

# Create a `for` loop that prints out each item in your variable that holds the output of the `ls` command.
for x in ${ls_out[@]}
do
  echo $x
done


# Bonus
# Create a for loop to print out execs on one line for each entry
for exec in ${execs[@]}
do
  echo $exec
done

```
