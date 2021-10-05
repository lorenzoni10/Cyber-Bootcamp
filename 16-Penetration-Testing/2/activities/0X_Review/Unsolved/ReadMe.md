## Activity File: Nmap Review
 
- In this activity, you will be reviewing some of the core concepts that we covered today as well as exploring new commands against a new target. 
 
- Specifically, you will be running scans against `scanme.nmap.org`, a website hosted by the maintainers of Nmap and designed to for users to practice their nmap skills.

- If you get stuck, refer to the nmap man pages. Feel free to work with a partner during this review. 


To get started, log into your Kali Linux VM in the Pentesting Lab Environment.


### Instructions:
 
Perform and answer the following questions:

Using nmap on the command line, run the following scans against `scanme.txt`:

1. Run a TCP Full-Connect Scan:
    - Which ports are open?

2. Run a service and version Detect Scan. Have the scan send the results to a new file named `scanme_results.txt`: 

    - What version of Apache are they running? 
  
    - What version of OpenSSH are they running? 

    - Looking at the scan results, what OS system is hosting the `scanme.nmap.org` website? 


Recently your coworker notified you that they had failed to scan their their target without getting caught. They explain that their scan was aggressive and noisy, thus alerting the target of their scans. 

3. Based on the scenario above and the scans we learned in class today, which scan did your coworker use? What are the indicators that this scan was used?


4. Based on the scans that we learned today, which scan should your coworker have used? What makes this scan stealthy? 

____

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.  All Rights Reserved.



