## Activity File: Exploiting Heartbleed with Metasploit 
 
- In this activity, you will act as a penetration tester tasked with gathering data leakage from the Heartbleed vulnerability.

- Remember, when using Metasploit, we search for the vulnerability, use the vulnerability, show and fill the options, and then exploit.


Use the following virtual environment:  
- Attacking machine: Kali Linux use the credentials `root:toor`
- Vulnerable web server: Heartbleed use the following credentials `vagrant:vagrant`
  

### Instructions
 
1. Open a terminal in Kali and start Metasploit:
 
    - Run the command that launches Metasploit.
 
2. Perform a search for all Heartbleed-related exploit modules:
 
    - Run the command that performs a search for `heartbleed` exploits.
 
3. Load the exploit module for use:
 
    - Run the command that loads the `auxiliary/scanner/ssl/openssl_heartbleed` module.
 
4. Check which options can be changed:
 
    - Run the command that shows the module options.

5. Configure the module's target using the victim's IP address and specify which MSF exploit module to use:
  
     - Run the command that sets the `RHOSTS` option to the given target's IP address.
 
    - Run the command that sets the `RPORT` option to the target's port `443`.

    - You'll also want to see the results of the attack: before you run your exploit, enter the command `set verbose true`.
 
6. Run the exploit. What were the results of the scan? Did you see any passwords? 
    - Remember, the Heartbleed vulnerability only sends data fragments. Try running the exploit a few more times if you were unable to discover any passwords. 
     

#### Bonus

Security experts will often create and publish their own scripts to share with each other. 

- From a security standpoint, it is not recommended to run scripts that you are not familiar with. 

- Similarly, we shouldn't always depend on scripts we discover online, as they are not as well-maintained as frameworks on Metasploit. 

However, for this bonus we have provided a script called `heartbleed.py`.

- In a new terminal window, switch to the `/opt/heartbleed-example/` directory and run the following command:

  - `./heartbleed.py -n 100 <victims IP address>`

Did you discover any new passwords? Are there differences between running this script and using Metasploit? What are they?
 
____
 
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
