## 16.1 Student Guide: Introduction to Pen Testing and Open Source Intelligence

### Overview

In today's class, you will be introduced to pen testing, why it's valuable to an organization's security, and discuss pen testing career pathways. We'll then move on to the first phase of pen testing using open source intelligence (OSINT) tools.

### Class Objectives

By the end of class, you will be able to:

- Understand the role of a pentester in assessing a business's security. 

- Do reconnaissance on a target network by performing basic DNS enumeration by viewing WHOIS record information.

- Gather domain information using OSINT techniques and tools like Google dorking, Shodan, and certificate transparency.

- Use Shodan and Recon-ng to discover domain server information. 

### Slideshow 

The class slides are available on Google Drive here: [16.1 Slides](https://docs.google.com/presentation/d/1VvCeDrtMkaqzrUtbikL6IV_PTToTiHf7zSq4F_PWZC8)



____


### 01. Introduction to Penetration Testing

Today we will begin learning about penetration testing. 

- We have covered a wide range of cyberattacks and vulnerabilities throughout the class so far. 

- Now we will look at a specific professional role that partners with organizations to assess their security postures, vulnerabilities, and susceptibility to attacks. 

Today we will cover: 

- An introduction to pen testing and its business goals.
- A high-level overview of the various stages of a pentest engagement.
- A deeper dive into the first step of a penetration test: reconnaissance.

 The techniques we will learn throughout this unit can be used to break into networks and do serious damage to an organization's infrastructure. This is illegal when done without permission. As such, understand that the tools and techniques discussed today are serious. Do not practice against computers you do not own or do not have clear written permission to be interacting with.


#### What is Pen Testing?

Penetration testing, often referred to **pen testing** or **ethical hacking**, is the offensive security practice of attacking a network using the same techniques that a hacker would use, in an effort to identify security holes and raise awareness in an organization. 

- While network administrators and security personnel do their best to harden their networks, it often takes an external entity to identify misconfigurations and subtle security holes.

- Organizations hire pentesters to assess their security controls. Pentesters find flaws in those controls, help the organization understand their flaws, and provide recommendations about which vulnerabilities to prioritize and how to fix them.

- Pentests are often administered by consultancies, which can take an "outside" view of a client's networks.

- A penetration test is often referred to as an **engagement** by practitioners.

In the simplest terms, pentesters aim to break a client's machine in order to help the client improve their security. 

Pentesters, unlike hackers, do this only after receiving permission from the security owner to begin an engagement.  

An engagement consists of five stages, similar to the stages of other offensive security practices we've looked at in past units: 

1. Planning and Reconnaissance
2. Scanning
3. Exploitation
4. Post Exploitation
5. Reporting

The next three class days will cover the first three stages of engagement:

- Day 1: Also known as Footprinting, the Planning and Reconnaissance process consists of both passive and active reconnaissance. It can also include social engineering campaigns with the goal of gathering as much information about a target as possible, along with gaining elevated privileges in an organization. 

- Day 2: Once we have access to the organization's infrastructure, we can perform scanning and enumeration techniques. Many of these require `sudo` privileges. This is an active process of engaging with a target to gather even more information. Here we will determine which computers are active on a network, and which of those machines might be good targets to carry out an attack.

- Day 3: After scanning an organization's network for vulnerabilities and mapping out our targets, we can execute the exploits that we know an organization is vulnerable to. This can include carrying out a number of attacks on various systems, including escalating privileges, cracking passwords, installing custom scripts and malware, etc.

This methodology is designed to mimic that of an actual attack. This helps network defenders understand how effective their organization's defenses are.

  ![Pentest](Images/PENTEST_1.png)


Penetration testers use a combination of automated tools (such as vulnerability scanners) and manual tools to research vulnerabilities, craft phishing emails, manually exploit hosts, and write shell code.

- Pentesters use these tools creatively, just as hackers do.

#### Types of Penetration Testing


There are three primary types of penetration tests: **no view**, **full view** and **partial view**. 

- **No view** testing, also known as black box, simulates a hacker who has no prior knowledge of the target system and network. They are paid to learn and exploit as much as they can about the network using only the tools available to an attacker on the public internet.

   - For example, they may only know the company name and be forced to find various key resources, like  IP ranges and access credentials. 

- **Full view** testing, also known as white box, is given full knowledge of the system or network. This knowledge allows them to tear apart subtle security issues on behalf of their clients. Full view pen testing is most appropriate when the client wants a detailed analysis of all potential security flaws, rather than all exposed and visible vulnerabilities.

   - Full view testers are given network diagrams, access credentials to the networks, system names, usernames, emails, and phone numbers.

- **Partial view** testing, also known as grey box, is performed by the in-house system or network administrator.
  

Regardless of the scenario, the main deliverable for pentesters is a report that summarizes their findings and recommendations for improvements.

While every pentest can be categorized as either full view, no view, or partial view, there are subtle differences between each engagement. For example: the extent to which the organization's employees know the engagement is happening and how much the pentester knows about the company. 


#### Understanding the Scope and Purpose of a Test

The organization and the pen testing team discuss the scope and purpose of an engagement before the penetration test in a Planning and Reconnaissance interaction. 

- This interaction takes place so the pentesters thoroughly understand the client's needs before beginning the test.

- Businesses are not primarily interested in how attackers might gain access to their networks. Instead, they are more concerned with how an exploited vulnerability might have major consequences on their reputation, operations, or bottom line.

The first form of contact is usually a kickoff call or meeting during which clients work with pentesters to determine the purpose and scope. During this stage, clients will:

- Clarify their needs and concerns and communicate which assets the business is most interested in protecting. This defines the purpose.

- Inform pentesters which machines and networks are off-limits and should not be targeted for attack. This defines the scope.

The pen testing team will scope their test accordingly, seeking to:

- Demonstrate potential business impact due to vulnerabilities in the network.

- Provide recommendations for mitigating those vulnerabilities in the future.

The primary deliverable from this stage is a document summarizing the engagement's purpose and scope, as well as associated details such as time frame, emergency contacts, etc.


#### Professional Insight: Penetration Testing 

Pen testing is a competitive and challenging field to enter.

- There are several paths to becoming a pentester. The most common path is to start as an SOC analyst, move up to security analyst, and then become a pentester.
  

Pen testing requires ongoing skill development. Therefore it is highly recommended that you establish and maintain a personal lab environment to practice in.

You may find that some employers will accept certifications in place of experience, but that this will not always be the case.

Next we'll explore the career outlook for penetration testers.



### 02. Activity: Certification Research


- [Activity File: Certification Research](activities/02_Cert_Research/Unsolved/README.md)



### 03. Activity Review: Certification Research


- [Solution Guide: Certification Research](activities/02_Cert_Research/Solved/README.md)


### 04. DNS and Domain Discovery 

By now, you should know that the first step to executing any attack is performing reconnaissance.

There are two types of reconnaissance: passive and active.
- **Active reconnaissance** is when you directly engage with a target system. For example, running a port scan directly on a server.
- **Passive reconnaissance** is when you try to gain information about a target's system and network without directly engaging with the systems.
   - To conduct passive reconnaissance, pentesters can use the massive amounts of both useful and superfluous information that already exist on the web. For instance, there are many third-party tools that may have already scanned a system. A pentester can use these third-party tools to get information without engaging directly with a system.

- Massive amounts of both useful and superfluous information exist on the web. The challenge is knowing what is important and how to extract it.

- Remember: offense informs defense. Adversaries have become experts at extracting information from the internet. We need to become experts too, so we can defend against it.
  

Today's reconnaissance will focus on external reconnaissance, also referred to as **open source intelligence (OSINT)**.


#### Introduction to OSINT

OSINT aims to gather publicly available information about a target. 

Since no view pentesters begin their engagement with very limited knowledge, they must use OSINT to gain as much information about a target as possible. 

- The information gathered in this stage plays a critical role in completing other phases of the engagement. 

- For example: OSINT intelligence such as IP address blocks can be used to perform network scans to determine if a target is behind a firewall.

- Other useful OSINT intelligence includes:

   - Usernames
   - Email addresses
   - Phone numbers
   - Domain names

We'll use a WHOIS database to acquire OSINT intelligence for a DNS registrar and try to enumerate IP addresses of a target.

- We'll use osintframework.com, a website that collects OSINT tools. These tools are freely available and can be used for information gathering across the web. 

- While other websites may require paid registration to access their resources, you should be able to complete the initial information gathering stage without any expenses.

   ![osint.com](Images/osint.png)

#### Legal Disclaimer

Gathering information about a person or organization using the public domain is legal.

  - Since OSINT involves gathering publicly available information, it is entirely legal.

  - Attempting to gain access to systems that do not belong to you or you do not have permission to access is *illegal*, and a potential felony.

   - For example, performing any of the following acts without the specific, written permission of the system's owner would be considered a felony:
      - Port scans
      - Brute force attacks
      - Social engineering


#### OSINT Demo 

For this demonstration, we will use the fictional company MegaCorp One.

- MegaCorp One is a fictional company created by Offensive Security. It was designed as a training tool to be used in the [Penetration Testing with Kali Linux (PTK)](https://www.offensive-security.com/pwk-oscp/) training.

Begin by launching the webpage osintframework.com. We'll use this for part of our demo.

1. Explore the website's interface by clicking on several circles, revealing the multifaceted branches of open source intelligence. 

2. After exploring the website, navigate to Domain Name > Whois Records > Domain Dossier.

   - Click on **Domain Dossier**. This will bring you to an external site called  centralops.net.

4. Enter megacorpone.com in the search box, check every box under the search bar, and click **Go**.

   - Look through the various records and note how they may be useful to attackers:

     - For example, employee names, number, email, and phone information could be used in a social engineering attack.

   - Scroll down to the DNS records. Review the different subdomains that belong to MegaCorp One. 

     - For example: mail.megacorpone.com and mail2.megacorpone.com are the names of mail subdomains, which could be useful to an attacker.

5. We'll use the mail.megacorpone.com domain that we found in our search.

   - Navigate to mail.megacorpone.com.

   - This brings us to MegaCorp One's email portal.

   - Note that the attacker can brute force a username and password.

   - Brute force attacks are easily mitigated with password lockout mechanisms.

      ![Outlook](Images/GHACK_OUTLOOK.png)

6. At this point, an attacker could perform a guessing attack or potentially use social engineering to persuade an employee to reveal their login credentials.

   - If we look at the bottom of the webpage, we see the web app name and year.

   - This provides attackers with hints about which vulnerabilities can possibly be exploited.

7. We can also use Google for OSINT. 

   - Using Google for OSINT purposes is called **Google hacking** and **Google dorking**.

   Open the following [Google Cheat Sheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf).

   - This sheet shows various operators that can narrow the parameters of a Google search. 

----

### 05. Activity: DNS and Domain Discovery

- [Activity File: DNS and Domain Discovery](activities/05_DNS_Domain_Discovery/Unsolved/README.md)



### 06. Activity Review: DNS and Domain Discovery Activity

- [Solution Guide: DNS and Domain Discovery](activities/05_DNS_Domain_Discovery/Solved/README.md)

### 07. Break

### 08. Google Dorking, Shodan, and Certificate Transparency 

We've learned about the role of DNS domain discovery in helping adversaries plan their attacks.

  - Now we'll explore some other TTPs used by attackers that will help us make informed decisions when safeguarding networks.

Google hacking, also known as Google dorking, is a technique that uses Google for OSINT and to discover security holes in a website's code.

Explore the following resources for more information:
- [Cybrary: Google Dorking Commands](https://www.cybrary.it/blog/0p3n/advanced-google-dorking-commands/) 
- [SANS.org: Google Cheat Sheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf)
- [My Hacking World: Google Dorking Tutorial](https://myhackingworld.com/google-hacking-and-google-dorking-basics/)

In this demonstration, we'll use Google to find information on MegaCorp One that could be useful to an attacker.

### Google Dorking Demonstration

We'll use a combination of Google search techniques to target MegaCorp One and gather information such as: 

- Employee email addresses
- Employees' first and last names
- Domain information
  

The goal is to find data that can be used to attack MegaCorp One.

**Important:** Google Dorking can enable a user to find webpages that are supposed to be hidden and unavailable. Accessing sensitive information in this manner can be illegal.

1. We'll continue to use the fictional website megacorpone.com.

2. In a browser, navigate to google.com.

2. Search: **site:megacorpone.com**

   - This is a very basic subdomain enumeration task that yields a variety of MegaCorp One's subdomains.

   - The file system shows up in the search results and we can see all the assets of the site.

      ![index](Images/index.png)

   -  This gives an attacker a deeper understanding of the site's file structure.

### Shodan

Another useful OSINT tool is **Shodan**, a search engine that searches specifically for computers and machines connected to the internet. It scans the entire web and reports back all of its findings in the browser window. 


#### Shodan Demo 

In the following demonstration, we'll use Shodan to acquire IP addresses. 

1. Go to to osintframework.com. 

   - Navigate to Domain Name > Whois Records > Domain Dossier

2.  Enter the domain example.com, and check all the search boxes. Click **Go**.

    - The search returns the IP address `93.184.216.34`.

       ![Domain Dossier](Images/7_5.png)

  - We also receive domain information that can be used by an attacker to perform attacks like DNS cache poisoning and DNS redirect attacks.

     - In this example, the organization is using the **DNSSEC**, a set of protocols that use public keys and digital signatures to verify data throughout the DNS lookup and exchange process. 

     - It adds an extra layer of security during DNS transport. 

     - You can learn more at [ICANN: DNSSEC – What Is It and Why Is It Important?](https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en) 

     ![Domain Dossier](Images/7_6.png)

  - Underneath the Network Whois record, we are presented with such information as:

      - Contact name: Derek Sawyer
      - Mailing address: 13031 W Jefferson Blvd #900, Los Angeles, CA 90094
      - Phone number: +18773343236
      
      This information can be used in a social engineering campaign.

    ![Domain Dossier](Images/7_7.png)

   - Access to DNS record information provides adversaries with alternative methods of attack, such as:


      - **Domain hijacking**: Alters registrar information in order to redirect traffic away from your DNS server and domain towards another destination.
    
      - **DNS flooding**: Overwhelms a server with malicious requests so that it cannot continue servicing legitimate DNS requests.
    
      - **Distributed reflection denial of service (DRDoS)**: Sends requests from its own servers with a spoofed source address of the targeted victim, causing all replies to flood the target.
    
     ![Domain Dossier](Images/7_8.png)

3. Now we'll use Shodan to see if there is any useful attack information for the acquired IP address.

   - Open a web browser and navigate to shodan.io.

   - Enter the IP `93.184.216.34` into the search box.

   - Shodan returns some critical information, such as port information, services running, and web technologies that can be used to attack the organization. 


   ![Shodan Results](Images/7_4.png)

Combining OSINT tools such as osintframework.com and Shodan provides more robust results. 


#### Certificate Transparency 

Certificate issuers publish logs of the SSL/TLS certificates that they issue to organizations.

- This **certificate transparency** can be exploited by attackers and used to search for subdomains. 

Open a web browser and navigate to the certificate searching tool at https://crt.sh. 

- Enter example.com into the search box.


- Contained within our search results are all the certificates associated with every variation of the example.com domain.

  ![CRT.SH Search](Images/7_10.png)

- If we click on the first certificate result, it reveals highly detailed information regarding the digital certificate (as seen below).

  ![CRT.SH Search](Images/7_11.png)

An attacker can use this information to perform domain hijacking, DNS flooding, and DRDoS.

### 09. Activity: OSINT Recon

- [Activity File: OSINT Recon](activities/09_OSINT/Unsolved/README.md)


### 10. Activity Review: OSINT Recon

- [Solution Guide: OSINT Recon](activities/09_OSINT/Solved/README.md)


### 11. Recon-ng 

We'll continue our Reconnaissance efforts with a tool called **Recon-ng**. 

- Recon-ng is a web reconnaissance framework written in Python.

- Recon-ng provides a powerful, open source, web-based reconnaissance framework that can be conducted thoroughly and quickly. It includes the following features:

  - Independent modules
  - Database interaction
  - Built-in convenience functions
  - Interactive help
  - Command completion 

There are many scripts and programs that can assist with integrating OSINT tools into Recon-ng.

  - Recon-ng is a framework that ingests a lot of popular OSINT modules, allowing the results of multiple tools to be combined into a single report.

  - Recon-ng also went through a major update recently. The following link details changes from version 4.x to 5.x and a set of new, handy commands that comes with the newer 5.x version. [Read about the changes.](https://www.blackhillsinfosec.com/wp-content/uploads/2019/11/recon-ng-5.x-cheat-sheet-Sheet1-1.pdf). 


#### Recon-ng Demonstration 

1. In Kali, start Recon-ng:

   - Run `recon-ng`

      ![Recon-NG](Images/RECON-NG.png)

   - Recon-ng doesn’t come preinstalled with modules, so you must download them as needed.
   
      -  All the necessary modules are already installed in our VMs.
   
   - We are getting the error `shodan_api key not set. shodan_ip module will likely fail at runtime. See keys add.` That's OK, since we'll be adding this key during this activity. 
   
2. We need to set an API key for modules that require it before they can be used.

     We'll set an API key for Shodan inside Recon-ng. This allows Recon-ng to ingest Shodan results.

   - Log into Shodan, click on **My Account** in the top-right corner and copy the API key to your clipboard.

   - **Note:** If you haven't already, register for a free account now at  shodan.io. Once registered, click on **My Account** in the top-right corner and copy the API key to your clipboard.

      ![My Account](Images/MY_ACCOUNT.png)
   
   - Copy your API key.
   
      ![](Images/api_key.png)
   
3. In Recon-ng, type `modules search` to view all of the currently installed modules.

   - For this activity, we'll use the following two modules:

     - `recon/domains-hosts/hackertarget`
     - `recon/hosts-ports/shodan_ip`

      ![Modules search](Images/MODULES_SEARCH.png)

4. Type `modules load recon/hosts-ports/shodan_ip` to load the `shodan_ip` scanner module.

   - Modules need to be loaded prior to modification and use.

   - Now that the module has been loaded, we can add the API key by typing:
   
      - `keys add shodan_api [key]`
      
         - Replace `[key]` with the one you copied to your clipboard earlier.

   - This API key allows information sharing between Shodan and Recon-ng. 

5. Type `keys list` to verify that it is imported.

6. Type `info` to get information regarding the Shodan module.

   - The `SOURCE` option is required. This option specifies which target Recon-ng will scan. This can be:

      - A list of IP addresses in a text file
      - Individual IPs
      - A domain name
   
   - For this example, we'll set the domain name `sans.org` as our `SOURCE` option.

      ![Empty Option](Images/EMPTY_OPTION.png)

   - Set the `SOURCE` to sans.org by typing `options set SOURCE sans.org`.

      ![Source Set](Images/INFO_SANS_ORG.png)
   
   - Using Shodan with a pro account allows you to query open ports on your discovered hosts without having to send packets to target systems.

7. We're now going to use an additional module called **HackerTarget**. 

   - HackerTarget will use Shodan to query all of the hosts that belong to sans.org. 

      - **Note:** Although HackerTarget can find hosts by itself, combining modules produces better scan results by discovering additional hosts that would otherwise be missed.

   Next, we'll load the `recon/domains-hosts/hackertarget` module and change its `SOURCE` to that of the target.

   - Type `modules load recon/domains-hosts/hackertarget`.

   - This will load the `recon/domains-hosts/hackertarget` scanner module.
     
   - Now that the module is loaded, type `info` to check the `SOURCE` setting.
   
      ![Update 1](Images/UP_1.png)
   
   - Set the `SOURCE` to sans.org by typing `options set SOURCE sans.org`.
   
   - The HackerTarget and Shodan modules serve two distinct purposes:

      - The HackerTarget module uses the `SOURCE` option to display scan results verbosely.

      - The Shodan module uses the `SOURCE` option to specify which target Recon-ng will scan. 
      
      ![Update 2](Images/UP_2.png)

8. From within the `hackertarget` module, type `run`.

   Recon-ng will query Shodan for sans.org.

   - The results will automatically display verbosely in the terminal window.

      ![RUN](Images/UP_3.png)

9. We have the results, but we would like a file to include into our report. Let's go ahead and install a new module. 

We're going to search for the `reporting/html` module in the Recon-ng marketplace.

   - Run `back` then `marketplace search reporting/html`

     ![hackertarget_search](Images/hacker_search.png)

To install the `reporting/html` module, we'll use the command `marketplace install reporting/html`.

   - Run `marketplace install reporting/html`

     ![hackertarget_install](Images/hacker_install.png)

10. Next, we'll load the `reporting/html` module, which allows the generation and output of reports.

   - Run `modules load reporting/html`

      ![Load Modules](Images/PARAMETERS_INFO.png)

11. Type `info` to see what parameters need to be set.

    The `CREATOR` and `CUSTOMER` parameters need to be set.

     - Set the `CREATOR` and `CUSTOMER` parameters using the `options set` command:

         - `options set CREATOR attacker`
         - `options set CUSTOMER Darkweb` 

    - Type `info` again after setting the options to verify the configuration worked.
    
      ![Empty Option](Images/PARAMETERS_INFO2.png)

    - Type `run` and the results will be saved to `/root/.recon-ng/workspaces/default/results.html`.
    
      ![Saved Report](Images/SAVED_REPORT.png)

12. View the report. 

      There are a few ways to view the report, but the easiest is to run: `xdg-open /root/.recon-ng/workspaces/default/results.html`.
   
    - `xdg` is a tool used to open files in text editors or, in this case, a browser. 

     In the **Summary** window, we can see that Recon-ng returned a result with 91 hosts.
    
    - Expand the **Hosts** window down by clicking the **+** sign to see all host information.

      ![Report](Images/REPORT.png)
    
    - At the bottom of the results page, we see the `CREATOR` option shown with the date and time.

      ![Report Creator](Images/REPORT_BOTTOM.png)

To summarize: 

- Recon-ng is a tool written in Python used primarily for information gathering by ethical hackers, such as penetration testers.

- Recon-ng comes preloaded with numerous modules that use online search engines, plugins, and APIs, which work together to gather information against a target.

- Network defenders use information obtained from Recon-ng to formulate mitigation strategies that help defend their networks.


### 12. Activity: Recon-ng

- [Activity File: Recon-ng](activities/12_ReconNG/Unsolved/README.md)


### 13. Activity Review: Recon-ng

- [Solution Guide: Recon-ng](activities/12_ReconNG/Solved/README.md)


&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.

