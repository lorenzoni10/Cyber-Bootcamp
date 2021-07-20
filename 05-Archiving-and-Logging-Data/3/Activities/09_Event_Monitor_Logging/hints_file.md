## Commands & Steps

- Use the `apt` package manager to install auditd.
- Check the status of auditd using `systemctl`
- Edit `/etc/audit/audit.conf` file and make modifications as the root user.
- Use `auditctl` using the `-l` option to list existing rule sets.
- Edit `/etc/audit/rules.d/audit.rules` to add new rules.
- Use `auditd` with the `-w` option to audit directories.
- Perform log searches using `auditd`  with the `-au`  option.
- Test auditd by creating a user account using `useradd`.
- Create a report for modifications of `auditd` using the `-m` option.