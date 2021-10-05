## Activity File: NSE Scripting


In this activity, you will continue your role as an independent penetration tester. 

- You will use the Nmap Scripting Engine and Zenmap to perform enumeration tasks against a target.

-  You will scan the Metaploitable VM to see if it is vulnerable to the specific vulnerabilities in the script.

- Be prepared to explain why you made certain decisions throughout the activity.  

In this activity, we will use the following two VMs:
   - Kali Linux use the credentials `root:toor`
   - Metasploitable 2 use the credentials `msfadmin:msfadmin`
 
### Instructions
 
1. We will first run a scan for the `ftp-vsftpd-backdoor`. 

   This is the same scan and vulnerability demonstrated in the previous section. You'll practice with this example first to familiarize yourself and gain some hands-on experience.  

   - Run the command to launch Zenmap from the command line in Kali Linux.
  
   - In the dropdown menu next to **Profile**, choose **Quick scan**.
 
   - Click the **Profile** tab at the top and select **Edit Selected Profile**.
 
   - Click the **Scripting** tab and view all the scripts that start with `ftp`.
 
   We're going to investigate a potential vulnerability on port `21` discovered from a previous Nmap scan.
 
      - Select the `ftp-vsftpd-backdoor` script by checking the box.
 
      - Click **Save Changes** to save the profile settings.
    
   - What is the raw Nmap command that Zenmap will run? Break down the syntax. 

 
2. Run the scan against the target host.
 
   - The scan results from the `ftp-vsftpd-backdoor` script should now be displayed within the Nmap output.
 
   - Analyze the output. What do you notice? 
 
3. Take 10 minutes to try other other commands and observe the results.
 
   - Be prepared to share your results with the class.
 
____

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
