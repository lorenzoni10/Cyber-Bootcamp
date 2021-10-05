#!/bin/bash

# Create Variables
nums=$(echo {0..9})
states=('Nebraska' 'California' 'Texas' 'Hawaii' 'Washington')
ls_out=$(ls)

execs=$(find /home -type f -perm 777 2>/dev/null)

# Create For Loops
# Create a loop that prints only 3, 5 and 7
for num in ${nums[@]}; do
  if [ $num = 3 ] || [ $num = 5 ] || [ $num = 7 ]; then
    echo $num
  fi
done

# Create a loop that looks for 'Hawaii'
for state in ${states[@]}; do
  if [ $state == 'Hawaii' ]; then
    echo "Hawaii is the best!"
  else
    echo "I'm not a fan of Hawaii."
  fi
done

# Create a `for` loop that prints out each item in your variable that holds the output of the `ls` command.
for x in ${ls_out[@]}; do
  echo $x
done

# Bonus
# Create a for loop to print out execs on one line for each entry
for exec in ${execs[@]}; do
  echo $exec

done
