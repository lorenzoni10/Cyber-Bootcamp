## Unit 7 README: Windows Administration and Hardening

### Unit Description

In our introduction to the Windows operating system, we will learn Windows-based system administration. We will cover the Windows operating system and command line by performing basic system administration tasks. We will depart from the standard command line by using the PowerShell command-line scripting language to create and execute scripts. We will also manage Active Directory Domain Services and secure a Windows Server domain.

### Unit Objectives 

<details>
    <summary>Click here to view the daily unit objectives.</summary>

  <br>

- **Day 1:** Introduction to Windows and CMD

    - Leverage the Windows Command Prompt (CMD) to navigate and manage directories and files.
    - Use `wmic` and Task Manager to manage processes and retrieve system info.
    - Create, manage, and view user information using the command-line tool `net`.
    - Manage password policies using `gpedit`.
    - Optionally, schedule tasks using Task Scheduler.

- **Day 2:** PowerShell Scripting
    - Use basic PowerShell cmdlets to navigate Windows and manage directories and files.
    - Use PowerShell pipelines to retrieve Windows system event logs.
    - Combine various shell-scripting concepts such as cmdlets, parameters, piping, conditions, and importing files with data structures.
    
- **Day 3:** Windows Active Directory Domain Services

    - Explain how Active Directory is used to manage enterprise-scale environments.
    - Define domain controllers as servers that manage AD authentication and authorization.
    - Use Active Directory tools to create organizational units, users, and groups.
    - Create and link Group Policy Objects that enforce domain-hardening policies.

</details>


### Lab Environment

This unit will use an online Azure lab environment. This environment consists of a Windows RDP Host machine that houses two nested virtual machines: a Windows 10 machine and a Windows Server machine. Use the following credentials:

- Windows RDP Host Machine

   - Username: `azadmin`
   - Password: `p4ssw0rd*`

- Windows 10 Machine (used on Day 3)
- Username: `sysadmin`
   - Password: `cybersecurity`
   
- Windows Server Machine (used on Day 3)

   - Username: `sysadmin`
   - Password: `p4ssw0rd*`

### What to Be Aware Of

- Don't forget to shut down your virtual machines and your Windows Azure lab at the end of each class and when they are not in use.

- You will be provided 30 hours of Azure lab access.

    - If you exceed that quota, you will be provided an additional 10 hours.

    - If you exceed those additional hours, you will be provided an additional 5 hours.

    - Once you exceed the final quota, you will not be provided any additional hours. It is extremely important that you preserve your allotted hours by shutting off your machines at the end of each class.


- The following document contains a list of common Windows issues that may occur during this unit. Review the content to prepare for potential troubleshooting:

    - [Windows Lab Environment Guide](https://docs.google.com/document/d/18Mz12q82nhxkypVRdIVgIqsLeNG1oCQj_TPsFJ3RgGk/edit)

### Security+ Domains

This unit covers Windows-based portions of the following domains on the Security+ exam:

- 2.0 Architecture and Design
- 3.0 Implementation

For more information about these Security+ domains, refer to the following resource: [Security+ Exam Objectives](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-security-sy0-601-exam-objectives-(2-0).pdf?sfvrsn=8c5889ff_2)


### Additional Reading and Resources

<details> 
<summary> Click here to view additional reading materials and resources. </summary>
</br>

These resources are provided as optional, recommended resources to expand on and solidify the concepts covered in this unit. 

- **Day 1 Resources**

 - [SANS - Windows Command Line Cheat Sheet](https://www.sans.org/security-resources/sec560/windows_command_line_sheet_v1.pdf)

 - [HowToGeek: Task Manager Guide](https://www.howtogeek.com/405806/windows-task-manager-the-complete-guide/)
  
 - [SS64: Windows Environment Variables](https://ss64.com/nt/syntax-variables.html)
  
 - [SS64: Command-line Overview of wmic](https://ss64.com/nt/wmic.html)
  
 - [Digital Trends: 32-bit vs 64-bit](https://www.digitaltrends.com/computing/32-bit-vs-64-bit-operating-systems/)
  
 - [Microsoft | Docs: wmic](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic)
  
 - [Digital Citizen: Net User Commands](https://www.digitalcitizen.life/how-generate-list-all-user-accounts-found-windows)
  
 - [wikiHow: How to Add Users from CMD](https://www.wikihow.com/Add-Users-from-CMD)
  
 - [Microsoft | Docs: Windows Release Information](https://docs.microsoft.com/en-us/windows/release-information/)
  
 - [Microsoft | Docs: net user](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11))
  
 - [Microsoft | Docs: net localgroup](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11))
  
 - [Microsoft | Support: Microsoft's net accounts documentation](https://support.microsoft.com/en-us/help/556003#:~:text=The%20%E2%80%9CNet%20Accounts%E2%80%9D%20command%20is,only%20used%20on%20local%20computer.)
  
 - [Microsoft | Docs: Security Identifiers](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-identifiers)
  
- **Day 2 Resources**

  - [Microsoft | Docs: PowerShell Cmdlet Overview](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7)

  - [SS64: PowerShell Parameters](https://ss64.com/ps/syntax-args.html)

  - [Microsoft | Docs: PowerShell Pipelines](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pipelines?view=powershell-7)

  - [Chocolatey.org: Why Chocolatey?](https://chocolatey.org/why-chocolatey)

  - [Chocolatey.org: How to Use Chocolatey](https://chocolatey.org/courses/getting-started/how-to-use)

  - [Chocolatey.org: Choco Uninstall](https://chocolatey.org/docs/commands-uninstall)

  - [Whatis.com: Circular Logging](https://whatis.techtarget.com/definition/circular-logging#:~:text=Circular%20logging%20is%20a%20method,limit%20on%20the%20hard%20disk)

- **Day 3 Resources**

  - [Microsoft | Docs: Active Directory Domain Services](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

  - [Microsoft | Docs: Creating Active Directory Users](https://docs.microsoft.com/en-us/windows/win32/ad/creating-a-user)

  - [Microsoft | Docs: Creating Organizational Units](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/adam/creating-organizational-units)

  - [Microsoft | Docs: Active Directory Security Groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)

  - [Microsoft | Docs: Creating GPOs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/create-a-group-policy-object)

  - [Petri.com: Create and Link Group Policy Object](https://petri.com/how-to-create-and-link-a-group-policy-object-in-active-directory)

- **Homework Resources**

  - [Microsoft | Docs: Access Control Lists](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)

</details>

---

### Unit 7: Homework 

For the homework, you will be expanding on domain-hardening Group Policy Objects and testing them. You will also create a PowerShell script to automate the retrieval of access control lists. 

This unit's homework assignment can be viewed here: 

- [Unit Homework File](../../2-Homework/07-Windows-Administration-and-Hardening/README.md)

### Looking Forward 

Next week, we'll be moving on to our Networking Module! We will start by learning the fundamentals of network configurations, designs, protocols, and data communication. We'll also be working in our Vagrant machines again. Make sure to pull the latest versions of the Vagrant lab.


---


© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
