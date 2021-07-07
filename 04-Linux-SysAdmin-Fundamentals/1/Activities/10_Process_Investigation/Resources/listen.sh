#/bin/bash

nc -lvp 4444 > /tmp/rev_shell.sh &
renice -n 1 $(pidof nc) 
