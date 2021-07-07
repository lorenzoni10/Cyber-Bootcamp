#!/usr/bin/env bash

# Check for root access
if [ "$EUID" -ne 0 ]
then
    echo "Please run this script with sudo"
    exit
fi

# Check for or create instructor research directory
[ ! -d /home/instructor/research ] && mkdir /home/instructor/research
[ ! -d /home/sysadmin/research ] && mkdir /home/sysadmin/research

# Copy needed files from instructor archive
cp -r /home/instructor/Documents/research/* /home/instructor/research
cp -r /home/instructor/Documents/research/* /home/sysadmin/research
echo "copied files to ~/research directory"

# Correct permissions and ownership on instructor research directory
chown -R instructor:instructor /home/instructor/research/
chmod -R 0744 /home/instructor/research/
echo "corrected permissions on ~/research directory and files"

# Correct ownership and permissions on the sysadmin research directory
chown -R sysadmin:sysadmin /home/sysadmin/research/
chmod -R 0744 /home/sysadmin/research/
echo "corrected permissions on the sysadmin/research directory"

# Copy over the motd file
cp /home/instructor/research/motd /etc/
echo "copied motd file into /etc"

# Install needed packages 
apt -y install john chkrootkit lynis &> /dev/null  
echo "installed john checkrootkit and lynis"
