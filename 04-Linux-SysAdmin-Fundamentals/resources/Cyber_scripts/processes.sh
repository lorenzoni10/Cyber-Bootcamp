#!/usr/bin/env bash

# Check for root access
if [ "$EUID" -ne 0 ]
then
    echo "Please run this script with sudo"
    exit
fi

# Start str.sh script from user jack
sudo -u jack /home/instructor/Documents/student_scripts/str.sh
