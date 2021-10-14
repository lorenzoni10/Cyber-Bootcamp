## Activity File: Attacking Shellshock with Metasploit 
 
In this activity, you will play the role of an independent penetration tester.

- You've been hired as a contractor to investigate suspicious activity on a company's web server. 

- Instead of using SearchSploit, you've decided to use the Metasploit framework because of its wide variety of module and configuration options.

- Specifically you will exploit Shellshock, create a shell session, and then read the `/etc/passwd` file.
  
Use the following virtual machine environment:

- Attacking machine: Kali Linux 
   - Username: `root`  
   - Password: `toor`

- Victim machine: ShellShock
   - Username: `vagrant`  
   - Password: `vagrant`


- Vulnerable web server: Shellshock

### Instructions

1. Open a terminal in Kali and start Metasploit:

   - Type the command that launches Metasploit.

2. Perform a search for all Shellshock-related MSF exploit modules:
   - Type the command that performs a search for the `shellshock` exploit module.

3. Load the exploit module for use:

   - Type the command that loads the `exploit/multi/http/apache_mod_cgi_bash_env_exec` module.

4. Check which options can be changed:
   - Type the command that shows the module options.

5. Now that the `exploit/multi/http/apache_mod_cgi_bash_env_exec` module is loaded, configure the module's target using the victim's IP address and specify which MSF exploit module to use:

     - Type the command that sets the `RHOSTS` option to the given target's IP address.

     - Type the command that sets the `TARGETURI` path to use the exploit module `/cgi-bin/vulnerable`.

6. Run the exploit:
     - Type the command that runs the exploit.

7. A Meterpreter session should now be open. 
   - Try to locate the hidden `flag` file on the exploited machine. 
   - **Hint** We'll cover this more in class next time, but try using Meterpreter's `shell` command to gain a **bash shell** into the victims machine.
 

____
  
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
