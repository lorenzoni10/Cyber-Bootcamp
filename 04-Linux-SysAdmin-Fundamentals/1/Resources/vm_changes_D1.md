# VM Changes

## General Server requirements:
Should be running standard Ubuntu

## Users Needed:

USER: root
Password: toor
- Should be able to login with bash shell
- Should have password: toor

USER: Instructor
Password: cybersecurity
- Should have full root/sudo access in sudoers file
- Should be part of the sudo group

USER: sysadmin
Password: cybersecurity
- Should have full root/sudo access in sudoers file
- Should be part of the sudo group

USER: jack
Password: lakers
- Should be part of the 'sudo' and 'hax0rs' group

USER: adam
Password: farrai
- Should have all default values
- Should be part of the 'hax0rs' group

USER: billy
Password: football
- Should have all default values
- no sudo access

USER: john
Password: john
- Should have all default values
- no sudo access

USER: sally
Password: 123456
- Should have all default values
- no sudo access

USER: max
Password: welcome
- Should have all default values
- Should have a copy of '/home/max/Documents/str.sh' file that only allows read/write access for max
- Should have an empty txt file: '/home/max/shopping_list.txt'
- Should be part of the 'hax0rs' group
- `sudo -l` should only show sudo access for `less`

USER: http
Password: website
- Should have a full home folder with default directories
- Should allow a login shell `/bin/bash`
- Should not be running any service

`/home/instructor/Documents/research_archive` should be created
This directory should contain:
- user.hashes
- files_in_root.txt
- files_in_home.txt
- packages_installed_by_admin.txt
- lst.sh
- user.hashes
- passwd
- shadow
- jack (home dir)
- http (home dir)
- files_in_bin.txt
- files_in_sbin.txt
- /var/logs/*

`/home/instructor/Documents/demo_scripts` should be created
This directory should contain:
- listen.sh
- rev_shell.sh
- a9xk.sh

`/home/instructor/Documents/setup_scripts` should be created
This directory should contain
- day2_instr_setup.sh
- day2_stu_setup.sh
- day3_setup.sh
- landmarks_demo.sh
- landmarks_review.sh

`/home/instructor/Documents/student_scripts`
- lst.sh
- day2_stu_setup.sh
- day3_setup.sh

`/home/sysadim/Documents/setup_scripts` should be created
This directory should contain
- day2_stu_setup.sh
- day3_setup.sh

Server should have `yes`, `stress-ng`, `stress`, `netcat`, `nano`, `vsftpd`, `xinetd`, `dovecot`, `top` and `apache2` packages installed.

## Sudoers file needs additions:
max  ALL=(ALL) /usr/bin/less

## Must have groups:
hax0rs
sudo
admin

## Default user values:
shell should be /bin/bash
  - Home Folder Directories:
	- Desktop
	- Documents
	- Downloads
	- Pictures
	- Public
	- Videos
  - No password expiration

---

## For Day 1

Instructor will run landmarks_demo.sh to remove student files and plant demo files before the demonstration

Instructor will run landmarks_review.sh to remove demo files and plant student files

Instructor and Students will run the processes.sh before the student activity and review

## For Day 2

Instructors will run day2_instr_setup.sh
Students will run day2_stu_setup.sh

## For Day 3
Students will run day3_setup.sh

---
