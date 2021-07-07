#!/usr/bin/env bash

# Check for root access
if [ "$EUID" -ne 0 ]
then
    echo "Please run this script with sudo"
    exit
fi

# Change apache2 port
sed -i 's~\<Listen 80\>~Listen 8080~g' /etc/apache2/ports.conf

# Start needed processes
systemctl start vsftpd xinetd dovecot apache2 smbd

# Set SUID bit for the `find` command
chmod u+s $(which find)

# Set user with erroneous UID
sed -i 's~^adam:x:.*~adam:x:0:0:/home/adam:/bin/sh~g' /etc/passwd

echo "Completed setup for day 3"