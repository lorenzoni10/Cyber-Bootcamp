## Activity File: Searchsploit and Shellshock

In this activity, you will be continuing your role as an independent penetration tester, you will use **searchsploit** to find a script that will verify if the machine is vulnerable to **Shellshock**.

Please note that the purpose of this activity is to not gain a backdoor into the Shellshock machine, but rather notifies you if the machine is susceptible to the ShellShock vulnerability. 

Although it's rare for a script that doesn't work "out of the box" there may be times when you're required to edit scripts in order to make them work properly.

A seasoned penetration tester should have the capacity to be able to modify **searchsploit** scripts on the fly. Not to worry, this comes with experience and a bit of trial and error.


### Instructions:


Use the following VMs to complete the activity:
   - Kali Linux use the credentials `root:toor`
   - ShellShock use the credentials `vagrant:vagrant`



You will be using this VM to verify the ShellShock vulnerability. 
    
1. Use Searchsploit to list all the available Shellshock scripts.

2. Identify the script that will exploit our webserver. 
 
3. Run the command that initiates the Python exploit script. Specifically, aim the script at the `/cgi-bin/vulnerable` page.

   - Hint: The format for running a SearchSploit python script is:
     
     - `python /usr/share/exploitdb/path_to_the_python_script payload=bind rhost=<TARGET IP ADDRESS> rport=<TARGET PORT> pages=/cgi-bin/vulnerable`
       - **Hint:** If you are unsure of which port to use, try to do a service scan using `nmap`

4. Was the script that you chose able to verify if the ShellShock machine was vulnerable? What would you recommend to a potential client? 

____


&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
