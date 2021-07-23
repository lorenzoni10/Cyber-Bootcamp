## Solution Guide: Creating Aliases

In this exercise, you created custom commands using aliases and the `~/.bashrc` file.

- You had to create the following aliases:

    - A custom `ls` command.
    - Custom commands to change directories into `Documents`, `Downloads`, and the `/etc` directory.
    - A custom command to easily edit the `~/.bashrc` file.
    - Custom commands for some of the compound commands you created in the previous activity.

- You also had to reload the `.bashrc` file so the commands took effect.

---

#### Solution

Log into the lab environment with the username `sysadmin` and password `cybersecurity`.

You can either add commands directly inside `~/.bashrc` using `nano`, or you can use output redirection to append them to the `~/.bashrc` file.

**Important**: Remember, you must use `>>` and not `>`, or else you will overwrite the entire file. It's recommended to make a backup of the `~/.bashrc` file before changing it.


Start by creating a backup copy of your `~/.bashrc` file by running `cp ~/.bashrc ~/.bashrc.bak`

1. Create an alias in your `~/.bashrc` file for `ls -a`.

    - Type `echo "alias lsa='ls -a'" >> ~/.bashrc`

        - `alias` indicated that the following code is an alias.
        - `lsa=` is the name of the new command. We can use anything we want, but we want to be careful not to use a command that already exists.

    - Note that we have to use a mixture of double and single quotes (`""` and `''`) here to get this command to work correctly.

        - `'ls -a'` is the command we are creating the alias for.

        - The echo command is wrapped in double quotes (`""`) and the alias is wrapped in single quotes (`''`).

    - `alias lsa='ls -a'` is the only line we need to add to our `~/.bashrc file`. If we wanted to add this directly to the `bashrc` file, we could use `echo` and redirection to do it in one line.

    - Run `echo "alias lsa='ls -a'" >> ~/.bashrc`
        
        - We could chain it together with `&& source ~/.bashrc` to automatically reload the file and enable the new alias.
        
        - Example: `echo "alias lsa='ls -a'" >> ~/.bashrc && source ~/.bashrc`



2. Create an alias in your `~/.bashrc` file for `cd ~/Documents`, `cd ~/Downloads`, `cd /etc`.

    Use the following command structure `alias docs='cd ~/Documents'` for each directory.

    - `~/Documents`:
        - Run `echo "alias docs='cd ~/Documents'" >> ~/.bashrc`

    - `~/Downloads`:
        - Run `echo "alias dwn='cd ~/Downloads'" >> ~/.bashrc`

    - `~/etc`:
        - Run `echo "alias etc='cd /etc'" >> ~/.bashrc`


These are the only lines needed for the `~/.bashrc` file.

Take a moment to see what's happening to the `~/.bashrc` file.

- Run `tail -4 ~/.bashrc`

    You should get output similar to:

    ```bash
    alias lsa='ls -a'
    alias docs='cd ~/Documents'
    alias dwn='cd ~/Downloads'
    alias etc='cd /etc'
    ```

---

#### Bonus Aliases

Create aliases for the following: 

- `nano ~/.bashrc`
- `mkdir ~/research && cp /var/logs/* /etc/passwd /etc/shadow /etc/hosts ~/research`

Create an alias in your `~/.bashrc` file for `nano ~/.bashrc`.

- Run `echo "alias rc='nano ~/.bashrc'" >> ~/.bashrc`

- Run `source ~/.bashrc` to reload the file and enable our commands.

- Run `lsa` to demonstrate your custom `ls` command.

- Run `docs` to demonstrate your custom `cd` command.

- Run `rc` to demonstrate your custom `nano ~/.bashrc` command.

Scroll to the bottom where the aliases are being added.

- The section should look like:

    ```bash
    alias lsa='ls -a'
    alias docs='cd ~/Documents'
    alias dwn='cd ~/Downloads'
    alias etc='cd /etc'
    alias rc='nano ~/.bashrc'
    ```

- Add a comment above your aliases to mark the section:

    ```bash
    # Custom Aliases
    alias lsa='ls -a'
    alias docs='cd ~/Documents'
    alias dwn='cd ~/Downloads'
    alias etc='cd /etc'
    alias rc='nano ~/.bashrc'
    ```


Complete the same steps for the following: 

1. `mkdir ~/research && cp /var/logs/* /etc/passwd /etc/shadow /etc/hosts ~/research`

    - **Solution**: `echo "alias logs='mkdir ~/research && cp /var/logs/* /etc/passwd /etc/shadow /etc/hosts ~/research'" >> ~/.bashrc`

    
The `Custom Aliases` section should now look like:

```bash
# Custom Aliases
alias lsa='ls -a'
alias docs='cd ~/Documents'
alias dwn='cd ~/Downloads'
alias etc='cd /etc'
alias rc='nano ~/.bashrc'
alias logs='mkdir ~/research && cp /var/logs/* /etc/passwd /etc/shadow /etc/hosts ~/research'
```

We can either keep the output file redirection `>> ~/research/users.txt` or we can leave it out. If we do leave it out, we can still use redirection when we run our custom alias.

- Save and quit Nano.

- Type `exec >> ~/research/users.txt` as an example of using redirection with a custom alias.

Remember, with every edit, you will need to reload the `~/.bashrc` file before the edits will take effect.

- Run `source ~/.bashrc`


--- 

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
