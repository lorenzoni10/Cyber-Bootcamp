## Unit 16 README: Penetration Testing

### Unit Description

This week, we will learn about pen testing and the steps to becoming a pentester, and then perform some basic reconnaissance using OSINT tools.

We will explore each stage of the pen testing process:

1. Planning and Reconnaissance
2. Scanning
3. Exploitation
4. Post Exploitation
5. Reporting

Each day will focus on a different stage.

### Unit Objectives 

<details>
    <summary>Click here to view the daily unit objectives.</summary>

  <br>

- **Day 1:** Introduction to Pen Testing and Open Source Intelligence
- An introduction to pen testing and its business goals.
    - A high-level overview of the various stages of a pentest engagement.
    - A deeper dive into the first stage of a penetration test: Planning and Reconnaissance.
    
- **Day 2:** Network Discovery and Vulnerability Scanning

    - Perform network enumeration using Nmap.
    - Properly use Nmap options. 
    - Explain what the Nmap Scripting Engine (NSE) is and how it's used.

- **Day 3:** Exploitation
- Run scripted Shellshock exploits.
    - Consult the Exploit-DB database to research publicly disclosed exploits.
    - Search for exploits and shellcode using SearchSploit.

</details>


### Lab Environment

This unit will use a new Pentesting lab environment located in Windows Azure Lab Services. RDP into the Windows RDP Host machine using the following credentials:

  - Username: `azadmin`
  - Password: `p4ssw0rd*`

Open Hyper-V Manager to access the nested machines, and use the following credentials:

**Kali machine:**

  - Username: `root`
  - Password: `toor`

**Metasploitable machine:**

  - Username: `msfadmin`
  - Password: `msfadmin`

**ShellShock:**

  - Username: `vagrant`
  - Password: `vagrant`

**Heartbleed**:

  - Username: `vagrant`
  - Password: `vagrant`

**DVWA10**:

  - Username: `IEuser`
  - Password: `Passw0rd!`


### What to Be Aware Of

Many of the techniques we study in this unit are illegal if used improperly or without explicit permission. Because of this, it is important to use these techniques only within the context of this class and the labs we provide.

### Security+ Domains

This unit covers portions of the following domains on the Security+ exam:

- 1.0 Attacks, Threats, and Vulnerabilities 
- 2.0 Architecture and Design 
- 3.0 Implementation

For more information about these Security+ domains, refer to the following resource: [Security+ Exam Objectives](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-security-sy0-601-exam-objectives-(2-0).pdf?sfvrsn=8c5889ff_2)



### Additional Reading and Resources

<details> 
<summary> Click here to view additional reading materials and resources. </summary>
</br>

These resources are provided as optional, recommended resources to supplement the concepts covered in this unit.

- [SANS.org: Pen Testing Cheatsheet](https://www.sans.org/blog/sans-poster-building-a-better-pen-tester-pdf-download/)

- **Day 1 Resources**
- [OSINT Framework](https://osintframework.com)
    - [Offensive Security: Penetration Testing with Kali Linux (PTK)](https://www.offensive-security.com/pwk-oscp/)
    - [SANS,org: Google Cheat Sheet](https://www.sans.org/security-resources/GoogleCheatSheet.pdf)
    - [Fictional SANS Site](http://megacorpone.com)
    
- **Day 2 Resources**

    - [NMAP.org](https://nmap.org/)
    - [NMAP Cheat Sheet](http://cs.lewisu.edu/~klumpra/camssem2015/nmapcheatsheet1.pdf)
    - [NMAP Scripting Engine](https://nmap.org/book/man-nse.html)

- **Day 3 Resources**
- [Wikipedia: Shellshock](https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29)
    - [Exploit Database](https://www.exploit-db.com/)
    - [Exploit Database: SearchSploit Documentation](https://www.exploit-db.com/documentation/Offsec-SearchSploit.pdf)

</details>

---

### Unit 16: Homework 

This unit's homework assignment can be viewed here: 

- [Unit Homework File](../../2-Homework/16-Penetration-Testing/Readme.md)

---


© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
