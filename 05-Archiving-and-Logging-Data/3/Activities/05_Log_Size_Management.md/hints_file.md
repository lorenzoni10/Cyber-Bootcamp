## Command & Steps

- `apt install logrotate`
- Modify certain sections in the file `/etc/logrotate.conf`
- `ls -lat /etc/logrotate.d`
- Create auth in /etc/logrotate.d

##### Example
```
/var/log/auth.log {
    rotate 50
    weekly
    notifempty
    compress
    delaycompress
}
```
- Create cron in /etc/logrotate.d - **Similar to the example above**
- Create boot in /etc/logrotate.d - **Similar to the example above**