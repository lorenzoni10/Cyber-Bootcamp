## Solution Guide: firewalld Configuration

The goal of this activity was to learn how to configure firewalld, a dynamically managed firewall that supports both network and firewall zones through trust-level definitions of network connections and interfaces.

### Solutions


1. List all available zones:


    - `sudo firewall-cmd --list-all-zones`


2. Set your `eth0` interface to your `home` zone:

    - `sudo firewall-cmd --zone=home --change-interface=eth0`


3. Display all active home zone services: 


   - `sudo firewall-cmd --get-services`
    
4. Verify the home zone setting:

    - `sudo firewall-cmd --zone=home --list-all`
        
    - What is the status of IVP6, SSH and Telnet?  

        - IPV6: Allowed
        - SSH: Allowed
        - Telnet: Missing (not allowed)
    
    - Are we able to connect via SSH or Telnet?

        - We can connect via SSH, because it's allowed.

5. Log into the UFW VM and connect to the firewalld IP:

     - `ssh 172.17.18.70 -l sysadmin`

        - You should connect without issue.
        - Type `exit` to disconnect.

6. Test Telnet to `172.17.18.70`:

    - Run `telnet 172.17.18.70`

    - What does the `no route to host` message mean?
        
        - This means that our firewalld program is blocking the connection.
 
7. Test pings to the `firewalld IP`.  
   ping firewalld IP

8. Switch back to the firewalld machine and block pings and ICMP requests in your `home` zone:

    - `sudo firewall-cmd --zone=home --add-icmp-block=echo-reply --add-icmp-block=echo-request`

9. List all the rules that are in place in your `home` zone:

    - `sudo firewall-cmd --zone=home --list-all`

    - Are all of our rules are in place?
         
         - Yes.

10. Switch back to the `UFW` and Run the command for `ping` that sends four packets to the `firewalld` machine.

    - `ping -c 4 172.17.18.70`

    - Are your ping requests blocked?

        - Yes.

#### Bonus:

11. Using `rich-rules`, block the UFW server's IP address:

    - `sudo firewall-cmd --zone=home --add-rich-rule='rule family="ipv4" source address="172.17.18.72" reject'`

12. Test if the UFW server's connection is blocked by testing your `rich-rule` by trying to SSH into `172.17.18.70`.

    - `ssh 172.17.18.70 -l sysadmin`
    
    - Why do you think you're not able to connect?

     - Because SSH or port `22` is being blocked.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
