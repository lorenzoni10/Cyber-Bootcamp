## Unit 17 README: Penetration Testing 2

### Unit Description

This week continues with our pentesting objectives from last week:

1. Planning and Reconnaissance
2. Scanning
3. Exploitation
4. Post Exploitation
5. Reporting

We continue with Exploitation and follow through the rest of the stages.

### Unit Objectives 

<details>
    <summary>Click here to view the daily unit objectives.</summary>

  <br>

- **Day 1:** Introduction to Metasploit
    - Use Metasploit to assist in various stages of a penetration test. 
    - Use SearchSploit to determine if the targets are vulnerable to exploits. 
    - Use exploit modules from the Metasploit framework to establish a reverse shell on a target.
    
- **Day 2:** Post Exploitation with Meterpreter 
    - Establish bind and reverse shells using Ncat.
    - Set Meterpreter payloads on a target.
    - Use Meterpreter shells to exfiltrate data from the target machine.
    
- **Day 3:** Custom Payloads with msfvenom
    - Create custom payloads.
    - Add payloads to websites by altering HTML. 
    - Assess overall penetration test engagement skills.

</details>


### Lab Environment

In this unit, you will be using the Pentesting lab environment located in Windows Azure Lab Services. RDP into the Windows RDP Host machine using the following credentials:

  - Username: `azadmin`
  - Password: `p4ssw0rd*`

Open Hyper-V Manager to access the nested machines with the following credentials:

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

- Many of the tools we study in this week are illegal if used improperly or without explicit authorization. Because of this, it is important to only use these tools within the context of the labs provided.

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

- **Day 1 Resources**
  
    - [Wikipedia: HeartBleed](https://en.wikipedia.org/wiki/Heartbleed)
    - [Exploit Database: SearchSploit Documentation](https://www.exploit-db.com/documentation/Offsec-SearchSploit.pdf)
    - [Sans.org: Metasploit Cheatsheet](https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)
    - [Wikipedia: Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug))

- **Day 2 Resources**
    - [SANS.org: Ncat Cheat Sheet](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
    - [PenTest-duck: Bind vs. Reverse vs. Encrypted Shells](https://medium.com/@PenTest_duck/bind-vs-reverse-vs-encrypted-shells-what-should-you-use-6ead1d947aa9)
    
- **Day 3 Resources**

    - [Red Team Tutorials: MSFVenom CheatSheet](https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/)
    - [The Dark Source: MSFVenom CheatSheet 3](https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/)

</details>

---

### Unit 17: Homework

This unit's homework assignment can be viewed here: 

- [Unit Homework File](../../2-Homework/17-Penetration-Testing-2/Instructions/README.md)

### Looking Forward 

Next week, we will focus on one of the most popular types of software that security professionals use to monitor their environments: **SIEM**, which stands for "security information and event management."

You will use your local Vagrant virtual machine for this week instead of a cloud environment.

---


© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
