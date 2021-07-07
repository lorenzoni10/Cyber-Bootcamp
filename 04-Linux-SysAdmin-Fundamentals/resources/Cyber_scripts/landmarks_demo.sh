#!/usr/bin/env bash

# Check for root access
if [ "$EUID" -ne 0 ]
then
    echo "Please run this script with sudo"
    exit
fi

#Remove Student files
rm /user.hashes
rm /tmp/str.sh

#Add teacher demo files
cp ~/Documents/demo_scripts/rev_shell.sh /tmp
cp ~/Documents/demo_scripts/listen.sh /tmp
cp ~/Documents/demo_scripts/a9xk.sh /tmp
