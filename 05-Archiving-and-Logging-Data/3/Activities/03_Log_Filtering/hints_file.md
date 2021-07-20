## Commands & Steps

- Use `journalctl` to query the systemd journal.  
- Use `journalctl -ef` to filter real-time journal messages.
- Use `journalctl _UID=<user_id>` to filter specific user journal messages.
- Check the journalctl config file to check it the Storage is uncommeted and set to auto. The file is located at /etc/systemd/journald.conf
- Restart the `systemd-journald`
- Monitor using the realtime journalctl monitoring command
- Create a fake user using `adduser` command.
- Try to add them to a privileged group - the command to add a user to a group is `usermod -aG <group> <username>`