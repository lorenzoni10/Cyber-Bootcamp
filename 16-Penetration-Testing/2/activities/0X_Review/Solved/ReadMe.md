## Solution Guide: Nmap Review
 
- In this activity, you will be reviewing some of the core concepts that we covered today as well as exploring new commands against a new target. 
 
- Specifically, you will be running scans against `scanme.nmap.org`, a website hosted by the maintainers of Nmap and designed to for users to practice their nmap skills.

- If you get stuck, refer to the nmap man pages. Feel free to work with a partner during this review. 


To get started, log into your Kali Linux VM in the Pentesting Lab Environment.


### Instructions:
 
Perform and answer the following questions:

Using nmap on the command line, run the following scans against `scanme.txt`:

1. Run a TCP Full-Connect Scan: `nmap -sT scanme.nmap.org`
    - Which ports are open?
 
    ```
    PORT      STATE    SERVICE
    22/tcp    open     ssh
    25/tcp    filtered smtp
    80/tcp    open     http
    5431/tcp  filtered park-agent
    9929/tcp  open     nping-echo
    31337/tcp open     Elite
    ``` 
    
 
2. Run a service and version Detect Scan. Have the scan send the results to a new file named `scanme_results.txt`: `nmap -sV -oN scanme_results.txt scanme.nmap.org`

    - What version of Apache are they running? 
      - `Apache httpd 2.4.7`
    - What version of OpenSSH are they running? 
      -  `OpenSSH 6.6.1p1`
    - Looking at the scan results, what OS system is hosting the `scanme.nmap.org` website? 
      - `Linux`


Recently your coworker notified you that they had failed to scan their their target without getting caught. They explain that their scan was aggressive and noisy, thus alerting the target of their scans. 

3. Based on the scenario above and the scans we learned in class today, which scan did your coworker use? What are the indicators that this scan was used?

    - Out of the scans we learned today, the co-worker probably used the TCP Full-Connect scan. TCP Full-Connect scans are an aggressive and noisy scan that will, in all likely cases, generate alarms on the targeted network alerting the target to the presence your scans. This is because network administrators will see rapid connects, and disconnects to their servers, causing abnormal traffic.

4. Based on the scans that we learned today, which scan should your coworker have used? What makes this scan stealthy? 


   - They should have used the TCP SYN Scan (also known as the Half-Connect scan). This scan sends a SYN packet and then waits for a response from the server, but never responds back to the server. SYN scans are relatively unobtrusive and stealthy since they never complete TCP connections.


____

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.  All Rights Reserved.
