### Student Audit Task Checklist

- [] Ensure that no one has added files to protected directories
  - [] Create a list of the files in the root directory
  - [] Create a list of directories in the home folder
  - [] Create a list of applications in the /bin directory
  - [] Create a list of applications in the /sbin directory
  - [] Create a list of applications installed by the admin with `apt list --installed > ~/research/packages_installed_by_admin.txt`

- [] Verify that only registered users are allowed to save files on the machine
  - [] Make a copy of `/etc/passwd`
  - [] Make a copy of `/etc/shadow`
  - [] Verify that all human users have passwords
  - [] Make a copy of any user home folders that should not be on the system

- [] Make sure that no suspicious programs have been installed on the system
  - [] Copy any suspicious script files you find

- [] Verify that the server has been saving log files, which contain important records of suspicious behavior
  - [] Make a copy of `auth.log`
  - [] Make a copy of `ufw.log`

- [] Ensure that attackers haven't saved malicious files in the "temporary files" directory, which is often abused by attackers
