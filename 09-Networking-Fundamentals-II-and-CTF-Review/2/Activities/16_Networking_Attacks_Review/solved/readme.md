## Solution Guide: Networking Attacks Review 

### Part One: ARP Attacks

Open the [network_attack_review.pcap](../../../resources/network_attack_review.pcap). 

1. Filter by ARP packets.

2. Review the packets captured, and explain in simple terms what is taking place in each of the three packets. 

    - **A device is asking who the owner of `192.168.47.254` is.** 

    - **A device responds "I am the owner, and here is my MAC address."**

    - **Then, a malicious device says, "Actually, I am the owner, here is a new MAC address."**

3. What type of attack is this? **This is an ARP posioning attack.**

4. What is the MAC address of the good device? **`00:50:56:f9:f5:54`**.

5. What is the MAC address of the hacker's device? **`00:0c:29:1d:b3:b1`**.

6. What negative impact might this type of attack have? **Traffic can be routed to the hacker's device instead of the correct, intended device.**

### Part Two: DHCP Attacks

Continue in the same PCAP.

1. Filter by DHCP packets.

2. Review the packets captured, and explain in simple terms what is taking place.  **There are many DHCP requests requesting IP addresses from the DHCP server.**

3. What type of attack is this? **DHCP starvation.**

4. Why is the destination IP `255.255.255.255` for all packets? **This is a broadcast IP, it is broadcasting the message across the whole local network to all devices.**

5. What negative impact might this type of attack have? **The DHCP server could run out of IP addresses and not be able to issue IPs to new devices connecting on the network.**

### Part Three: TCP Attacks  

Continue in the same PCAP.

1. Filter by TCP packets.

2. Review the packets captured, and explain in simple terms what is taking place. **There are many SYN requests. These are checking all the ports to see which are open.**

3. What type of attack is this? **SYN Scan.**

4. Is this type of activity always an attack? In other words, can a security professional benefit from what is taking place? **A security professional can use this same method to determine which ports are open in case they need to close them.**

5. What negative impact might this type of attack have? **A hacker could use this method to determine what ports exist, and which are open. Then the attacker could launch attacks against the open ports, as the ports can identify what services are potentially running.**

### Part Four: Wireless Attacks  

Answer the following questions.   

1. What are the different security types available for Wireless communications? List them in order from least to most secure. **WEP > WPA > WPA2.**

2. What is 802.11? **Standards for wireless network devices.**

3. What is an SSID? **The service set identifier is the name of a wireless network.**

4. What is the name of the the signal a WAP sends out identifying its SSID? **Beacon**.

5. If a user has WEP encrypted wireless, what is a potential negative outcome? **With WEP, an attacker could potentially find the decryption key from wireless traffic. The attacker could then use that key to decrypt the encrypted traffic.**

### Part Five: Email Attacks  

Open [email_reviews.pdf](../../../resources/email_reviews.pdf).

1. Review the two emails and their headers and determine if the emails are legitimate or spoofed.

2. Document your findings and summarize why you believe the emails are legitimate or spoofed.

**Based on the headers, The first email is likely legitimate.**

- From: TurboTax customercare@turbotax.com—the names match.

-  Received-SPF: The SPF record passed.

- The IP of `12.179.134.145`, from the Received header, belongs to Intuit, the owner of TurboTax, according to arin.net. 

**Based on the headers, The second email is likely not legitimate.**

- From: FedEx <asdc789asd@yahoo.com>—the names do not match.

- Received-SPF: The SPF record failed.

- The IP of `12.179.134.145`, from the Received header, comes from South Africa and has no relationship to FedEx, according to arin.net. 
