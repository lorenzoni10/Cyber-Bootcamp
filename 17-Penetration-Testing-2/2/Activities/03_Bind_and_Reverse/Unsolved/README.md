## Activity File: Bind and Reverse Shells and Netcat

In this activity you will be taking on the role of a pentester during the post-exploitation phase of a penetration test.

- At this point, you've already breached the victim's machine. Since you want to be able to return to it, you need to create a backdoor onto the machine.

- You are tasked with using Ncat to create bind and reverse shells.

Use the following machines: 

- Attacking machine: Kali Linux 
  - Username: `root`
  - Password: `toor`

- Victim machine: Metasploitable VM
  - Username: `msfadmin`
  - Password: `msfadmin`


### Instructions

1. **Bind shell**: Using Ncat, set up a listener on the victim's machine so you can connect to it from the attacker's machine. After testing it, document the following: 

    - Which commands did you run on the Metasploitable machine? 

    - Which commands did you run on the Kali machine?

    -  Explain the syntax of of any options used.

 
 
2. **Reverse shell**: Using Ncat, set up a listener on the attacker's machine that is prepared for the victim's machine to connect back to it. After testing it, document the following: 

    - Which commands did you run on the Metasploitable machine? 

    - Which commands did you run on the Kali machine?


#### Bonus

Re-exploit the victim's machine, and create a `hacked.txt` file in their home folder. Verify you created the .txt file successfully by logging into the metasploitable machine and reading it. 

---
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
