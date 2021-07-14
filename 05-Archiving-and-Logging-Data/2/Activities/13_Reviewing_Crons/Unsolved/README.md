## Activity File: Reviewing Crons

- As a junior administrator at Rezifp Pharma Inc., you have been using `tar` and `cron` to schedule user and system-wide jobs for maintenance and security tasks.

- A recently instated company-wide mandate is requiring the all IT staff to take bi-monthly assessments based on their job's defined operational procedures. Today's assessment is based on `tar` and `cron`. 


### Instructions 

1. Answer the following `cron` assessment questions:

    - When will the following `cron` schedules run?

      - `*/10 * * * *` 

    - What event is the following `cron` a minute away from?

      - `59 23 31 12 *`

    - What do the following hypothetical `cron` likely do?

      - `0 22 * * 1-5 /home/Bob/Sales/sum_of_sales.sh`

      - `@weekly /home/sysadmin/Scripts/auto-update.sh`


2. Answer the following `script` assessment questions:

    - What is a shebang?

    - What two characters should come before the filename of a script?

    - Jane's script has user and group ownership of a script with `-rw-r--r--` permissions, but she cannot get it to run. What must she do to the file before it will run?


3. Answer the following `tar` assessment questions:

    - How does the `-x` option modify the `tar` command?

    - If a directory has `ten` files and the following command is used in it, how many files are being archived?

      -  `tar cvvWf backups/archive.tar .`

    - What option prints the full file specification of files as you interact with them?

    - Why is the `-f` option used in almost every `tar` operation?

4. **Bonus**: You are tasked to look through the `cron` jobs within your current workstation to see if any suspicious or modified cron jobs exist. Remove the one that matches the following descriptions:

   - `Cron` is running system-level jobs with `root` privileges.

   - The `cron` task you're looking for involves another machine.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  