## Solution Guide: Metasploitable Report

In this activity, you had to review and present the results of a vulnerability scan to your client. 

---


#### Samba Badlock Vulnerability


1. What is the primary purpose of Samba? 

    - The Samba server allows machines of different operating systems to share resources. 
    
    - For example, if a user is using a Windows computer and needs to share files with Mac or Linux users, they can upload the file to the Samba network share, where the other users can access it.

2. Based on the scan results, how is our Samba server being exploited? 

    - Currently, our version of Samba is susceptible to man-in-the-middle attacks, in which hackers connect to the communication between our employees and our server.

3. How can we patch this vulnerability?

    - We need to update our Samba version as soon as possible.

4. What are some of the disadvantages of fixing this vulnerability?

    - When we're updating to the newer Samba version, users will not be able to access their file shares.


#### NFS Exported Share Information Disclosure

1. What is the primary purpose of a network file system (NFS)? 
    
    - Similarly to Samba, the NFS system contains files shared between users.

2. Based on the scan results, how is our NFS being exploited? 

    - NFS does not have the capability to implement authentication or encryption. Therefore, hackers can connect directly to the system, read and possibly write to the files that are on there.

3. Because NFS does not support authentication or encryption, how would you suggest fixing this vulnerability (assuming that our other servers are patched and don't have vulnerabilities)?  

    - We should move all of our data to the upgraded Samba server as soon as we can.

4. If we wanted to fix this, how would it affect our day to day business activities, such as how our users share files?

    - Because of privacy laws and the severity of the threat, we need to make a backup of the system and take it offline for the migration to the Samba server.


**Unencrypted Telnet Server**

1. What is the purpose of Telnet?

    - Telnet is an older protocol that can be used to send files and connect to the Metasploitable server.


2. What port does Telnet use?

    - Telnet uses port `23`.


3. What protocol should we use to connect to the server?

    - All users should use the SSH service, which encrypts data before sending.




----

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.
