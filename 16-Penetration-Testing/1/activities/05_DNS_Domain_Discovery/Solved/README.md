### Solution Guide: DNS and Domain Discovery

In this activity, you played the role of a junior penetration tester demonstrating your skills to SecureWay, a prominent security testing organization. 

---

1. Navigate to centralops.net. 

     **Bonus:** Navigate to the website from osintframework.com.  

    - Navigate from Domain Name > Whois Records > Domain Dossier > centrolops.net.

2. Enter any website of your choice into the Domain Dossier and view the DNS records of that site.

   - This solution uses google.com as an example. 
 
3. Scroll down to the **Network Whois record** section. 
 
    The interviewers asked you to view the NetRange and CIDR, and want you to answer the following question: Why is this information useful and how can an attacker leverage it?

    - NetRange: `216.58.192.0 - 216.58.223.255`
    - CIDR: `216.58.192.0/19`

   - NetRange and CIDR provide attackers with the IP information of hosts, which is needed to perform network scans. This allows attackers to perform firewalking, enumerate network topology, and fingerprint operating systems.
 
5. Scroll down to the **DNS records** section. Why is this information useful?

    - This information is useful to an attacker who wants to use DNS to redirect traffic, as a covert channel, and for reconnaissance.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.