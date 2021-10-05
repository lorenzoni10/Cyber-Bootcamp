## Activity File: Port Scanning with Nmap

In this activity, you will play the role of an independent penetration tester hired to use Nmap to simulate malicious port scans of a host.
 
- Nmap offers many different scanning options. Experiment with them and think about how each one applies to your pentest and the client.
  
- Keep in mind that each scan type has a unique purpose. Choosing the right one can save a lot of time and effort.

- **Note:** You will need to perform research to answer some of the questions regarding vulnerable services. 

### Instructions

For this activity you will use the following two VMs: 

   - Kali Linux VM use the credentials `root:toor`
   - Metasploitable 2 VM use the credentials `msfadmin:msfadmin`


1. Perform a basic TCP connect scan against Metasploitable 2.

   - Run the command to perform a TCP connect scan.
    
   - Of the ports listed, which two present the biggest potential vulnerability and why?

Discovering open ports is useful, but it's even more useful to know which services are listening on each port.

For example, if port `80` is open, we know it's probably a web server. But we'll need to find out if its Nginx, Apache or some other service if we want to properly exploit it. 

2. Run the command that performs a service and version detection scan against the target.
   
   Notice that in addition to the service type, Nmap displays the enumerated version numbers.
   
   -  What web service and version is running?
      
   - Is this web service version vulnerable? If so, what is the vulnerability?
      
 4. Look at port `21`. Google VSFTPD v2.3.4.
      - What does this tell you about this software and version?
   
      - How is this information useful to an attacker?
    
   
3. Experiment with using various scan techniques and interpret the results. 

   - Type `nmap` at the command prompt to get a list of commands that you can play with.

      - You can also go to [Nmap: Options Summary](https://nmap.org/book/man-briefoptions.html) for more info on using Nmap.

   - Be prepared to talk about which scans you ran. 
   

----

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
