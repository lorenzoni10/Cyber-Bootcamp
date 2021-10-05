## Activity File: OSINT Recon 

After your impressive interview with SecureWay, you were hired as a junior pentester!

- SecureWay was hired by MegaCorp One to evaluate the security of their business.

- As a junior pentester, you will perform an initial information gathering recon of their network using  Google dorking, Shodan, and certificate transparency techniques. 

 **Reminder:** OSINT is legal, but brute forcing and performing active scans is not. Do not attempt to log into or scan any websites during OSINT activities.

### Instructions

1. Using the [Google Cheat Sheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf), perform Google dorking on MegaCorp One to obtain as much information as possible.

    - Look for employees, email addresses, other associated domains, etc.
   - Briefly explain how your findings could be used in an attack.


2. Using Shodan and the information gathered from Google dorking, see if you can find any other useful information that can be used in an attack.

**Hint:** You may need to use tools _other_ than [CentralOps.net](https://centralops.net/) to get some IP addresses for megacorpone.com. Explore the other DNS tools provided on [OSINT Framework](https://osintframework.com/).

    - What open ports and running services did Shodan find?
    
    - What kind of attacks can be used on those ports? 

3. Now we'll practice exploiting certificate transparency by looking for exposed domains. 

      MegaCorp One believes its domains are not exposed, but would like you to demonstrate what information can be revealed by exposed domains, and how that information can be used for harm. 

   - Using the site https://crt.sh, see if you can answer the following about another site, sans.org.

     - Can you find any interesting subdomains?
     - How might an attacker use this information?

4. Do some research and find two methods for mitigating the threat posed by certificate transparency.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
