## Solution Guide: Meterpreter Basics

In this activity, you identified and researched specific commands that we will use throughout the unit. 

---

#### Meterpreter Basics
 
1. In your own words, what is Meterpreter?

   - Meterpreter is a reverse shell used as part of the Metasploit framework. We can use it like a normal backdoor, but it also comes equipped with many useful commands and features provided by Metasploit.
 
2. When connecting to the remote host, does Meterpreter start new processes similar to SSH and Ncat?
  
   - Unlike SSH and Ncat, Meterpreter does not start any new processes on the victim. Instead, it "injects" itself into a program that's already running.

3. True or False: Meterpreter encrypts all communication to and from the victim machine.

   - True

#### Basic Meterpreter Commands

Assuming that you have a Meterpreter shell, answer the following:

1. What command would you use to display the help menu?

   - `?`
 
2. What command would you use to identify detailed Windows privilege information?

   - `run win_privs`
 
3. What command would you use to gather the victim's system information?

   - `sysinfo`

4. What command lets you upload a `readme.txt` to your victim's computer?

   - `upload readme.txt`

#### BONUS

Attackers often try to get a Meterpreter shell by tricking their victims into downloading an executable file that they've created. How is the file created in Kali? 
  - **Hint:** Read through the process [here](https://www.offensive-security.com/metasploit-unleashed/msfvenom/).

    - Create a custom payload using `msfvenom`.

    - Send your target to your payload.

    - Set up a listener using Metasploit.

       - For example: Running `use windows/meterpreter/reverse_tcp` and `set payload windows/meterpreter/reverse_tcp` and then defining the `LHOST` and `LHOST`. 

    - Wait until the victim has executed your exploit. 

If you were unable to complete the bonus, don't worry about it! We will be covering `msfvenom` in our upcoming section. 

____

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.


