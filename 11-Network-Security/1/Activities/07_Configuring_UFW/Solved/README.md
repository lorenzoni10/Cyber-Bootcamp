## Solution Guide: Configuring UFW

The goal of this activity was to learn how to configure UFW by settings various firewall rules and observing their related effects against the network.

--- 

### Solution

1. Test that you can SSH into the Ubuntu UFW using Ubuntu firewalld. The firewalld VM will be used to test connections to the UFW VM.

    - Log into the firewalld VM with the following credentials:
 
      - Username: `sysadmin`
      - Password: `cybersecurity`

    - Attempt to use SSH to log into the UFW VM.

        -  Make sure to use the IP address for the `Eth0` interface of the Ubuntu UFW. 

        - Run the command to SSH: `ssh sysadmin@UFW IP`

        - Type `exit` to terminate the connection.

    - Now that you know you can log in using SSH, use UFW to stop that from happening.

2. Switch back to the Ubuntu UFW. We want to use UFW to block any and all incoming connections, unless specified, and we want to allow our machine to connect to any other machine. This will help keep our VM secure. To do this, block all incoming traffic while allowing all outgoing traffic.

    -  Type the commands that will set up the default rules blocking all incoming and allowing all outgoing:

        - `sudo ufw default deny incoming`
        - `sudo ufw default allow outgoing`

3. Block all incoming SSH connections:

   - Run `sudo ufw deny ssh`

   - This command tells UFW to block any incoming traffic using the SSH protocol. You should see UFW confirm the rule change.

    - Note: Alternatively, you can also block SSH port `22`. UFW will look in the `/etc/services` file to convert protocol names to port numbers.

4. Since Telnet is insecure and should never be used, configure your firewall to block it as well.

    - Run the command that will block Telnet:

      - `sudo ufw deny telnet`

5. In order to use your VM, you need to open a few common ports to allow information from web servers and mail applications.

    - Run the six commands that allow the necessary ports:
        - `sudo ufw allow 80`
        - `sudo ufw allow 143`
        - `sudo ufw allow 587`
        - `sudo ufw allow 110`
        - `sudo ufw allow 443`

6. After updating any rule in UFW, stop and restart it.

   - Type the command that enables UFW: 

     - `sudo ufw enable`
   
   - UFW should reply with an alert that it is enabled and ready to go.

   You can check the rules that have been assigned to UFW by checking UFW status:
     
     - `sudo ufw status`

7. Use the SSH protocol to try and connect to the UFW VM:

    - `ssh sysadmin@UFW IP`

    - Press Ctrl+C to stop your terminal from processing.

    - You have confirmed that the Ubuntu UFW VM will block all incoming SSH traffic.

8. Recall that you blocked Telnet but opened up port `80`. What will happen if you try to use Telnet on port 80?

    - Run the command to `telnet` to port `80`:

        - `telnet 172.16.18.72 80`

    - Enter any letter. You should see that the web server contacted on port `80` and the `HTTP` headers retrieved.    
    
    - Why is it able to make the connection with Telnet even though you blocked Telnet?
    
       - The blocking happens at the port level. Telnet normally runs on port `23`, but you are making the connection to port `80`, which was specifically allowed. 
        
        - In fact, if you ran a Telnet server on port 80, your current rules would allow it.

        - Also, using the Telnet client to connect to a web server cannot be distinguished from a normal web browser without some deeper analysis. At a superficial level, it looks exactly the same as a regular web browser.


9. Switch back to the UFW VM. Delete your initial rule blocking SSH. It is no longer needed because you are actively blocking all incoming connections.

    - Run the command that deletes the first rule only:

        - `sudo ufw delete 1`
    
    - You will be prompted to delete your `deny 22` rule.  If you did not block SSH as your first rule, enter `sudo ufw status` and determine the line number of your `deny 22` rule. Add that line number to the end of the command. 

     - For example: If your rule `deny 22` was line five, your command would be `sudo ufw delete 5`.

#### Bonus: 

10. You have blocked all incoming traffic except for the protocols deemed essential. Now you will allow the firewalld's IP address to access to your VM via SSH:

    - `sudo ufw allow from 172.16.18.70 to any port 22`

    - To recap, you now have a rule in place that blocks all incoming traffic and a rule allowing firewalld VM's IP address to connect on port `22` to UFW VM.
    

11. Switch back to the firewalld VM and test using SSH again:

    - Run the command to SSH into `172.16.18.72`:

        - `ssh 172.16.18.72 -l sysadmin`

    - You should have access again.

    - Exit out of the active SSH connection.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

