## 21.1 Student Guide: Introduction to Digital Forensics
 
### Overview
 
Today's class will introduce the digital forensics field. The class covers procedures for collecting, preserving, analyzing, and reporting forensics evidence. 
 
### Class Objectives
 
By the end of the class, you will be able to:
 
- Summarize the basic principles and methodologies of digital forensics.

- Describe various skill sets required for digital forensics jobs.

- Outline the proper approach to collecting, preserving, analyzing, and reporting forensic evidence.

- Conduct a preliminary review for a forensic case.

- Preserve and document evidence using Autopsy.
 

### Lab Environment

In this unit, you will be using a new Forensics lab environment located in Microsoft's Azure Lab services. Within this environment, you will find a Windows RDP Host Machine containing a **Kali linux** machine. 

Using RDP, log into the new environment with the following credentials:

  - Username: `azadmin`
  - Password: `p4ssw0rd*`

Today's lectures, demonstrations, student activities and reviews will be completed using the **Kali linux** VM. Use the following credentials to log into the **Kali linux** machine:

  - Username: `root`
  - Password: `toor`
  
The lab should already be started, so you should be able to connect immediately. 

Refer to the [lab setup instructions](https://cyberxsecurity.gitlab.io/documentation/using-classroom-labs/post/2019-01-09-first-access/) for details on setting up the RDP connection.  
 
### Slideshow
 
- [21.1 Slides](https://docs.google.com/presentation/d/1Ble9WWgKaFb7lyXEwZ4Acd1bxNJeEua-SzDPXslHU2Q/edit).
 
---
 
### 01. Welcome and Overview (0:05)
 
Digital forensics is a very exciting cybersecurity field  that requires a unique set of skills.

  - We learned in earlier units that penetration tests attempt to discover vulnerabilities in order to prevent breaches and cybercrimes.
 
  - We know that not all defenses can withstand the network attacks that are constant in today's cyber landscape. 
  
  - Therefore, digital forensics attempts to discover evidence of a crime after it's been committed. 

We'll begin class by introducing the field of digital forensics and describing the field's roles, skill sets, and responsibilities.

#### Roles, Knowledge, and Skill Sets

Digital forensics professionals must have a thorough understanding of hardware, operating systems, and computer networks. 
 
- The following link from NICCS details skills, knowledge, and other aspects associated with digital forensics:
 
  - [Cyber Security Workforce Framework: Digital Forensics](https://niccs.us-cert.gov/workforce-development/cyber-security-workforce-framework/digital-forensics)
 
Roles and responsibilities in the field of digital forensics are not well-defined across job titles. Specific job roles and responsibilities vary by organization, but may include the following:
 
- **Computer forensics investigators**: Gather digital information for computer system investigations, producing criminal evidence that can be used in a court of law. 
  - Legal cases involve data theft, espionage, and cyberwarfare. 
  
  - This career field involves analyzing data found on hard drives, network communications, and cloud-based data communication systems, as well as the production of reports and possible testimony in a court of law.
 
- **Computer forensics technicians**: Digital detectives who work with law enforcement or government entities, or as private investigators. 

  - Use investigative and computer analysis techniques to acquire, analyze, and preserve digitized evidence to be used for legal purposes. 
  
  - Inspect storage media and retrieve corrupted and deleted files from computing storage media, such as hard drives, removable flash media, and mobile devices. This material is used in legal proceedings.
 
- **Forensic computer analysts**: Specialize in the recovery of deleted emails or other data that has been encrypted or deleted. This material is used in legal cases involving computer crimes. 

  - Evidence produced by forensic computer analysts is used by law enforcement to assist with ongoing investigations. 

  - Evidence may also be used in a court of law to help convict criminals involved in computer crimes with cases related to child pornography, drug sales, or corporate espionage, among others. 
 
----
 
### 02. Introduction to Digital Forensics 
 
#### What Is Digital Forensics?
 
Digital forensics is a field dedicated to identifying, extracting, preserving, and reporting on information obtained from computer and network systems.
 
- The following definition of digital forensics was published in the article ["Digital Records Forensics: A New Science and Academic Program for Forensic Readiness"](https://pdfs.semanticscholar.org/9b0d/4752f2212a02541bf863a49bc2c2944e4ea2.pdf) in the *Journal of Digital Forensics, Security and Law*:
 
   “The use of scientifically derived and proven methods toward the preservation, collection, validation, identification, analysis, interpretation, documentation and presentation of digital evidence derived from digital sources for the purpose of facilitating or furthering the reconstruction of events found to be criminal, or helping to anticipate unauthorized actions shown to be disruptive to planned operations.” 
  
 
#### Legal Requirements
 
Why is it important to preserve the integrity of digital evidence?

- Forensic evidence that is intended to be used in legal proceedings must satisfy a set of legal standards in order to be admissible.
 
- Imagine the disappointment of spending months searching through computer and network systems collecting evidence, only to have it considered inadmissible and thrown out due to improper procedures.
 
- Forensic evidence is held to the same standards as any other evidence submitted in a legal case. All evidence must be wholly intact and unaltered from the scene of the crime.
 
- Once evidence is collected, the investigator or analyst is accountable for its ownership and whereabouts at all times.
 
#### Chain of Custody
 
A **chain of custody** is a documentation of the possession of evidence.
 
- Evidence taken into custody must be accounted for. This means that its whereabouts and ownership must be accurately documented at all times, from the time it is acquired to when it is presented in the court room.

- When testifying about the integrity of evidence, one must be able to provide a documented, uninterrupted chain of custody, which includes:

  - A detailed log of each person who accessed or handled the evidence.
  - The purpose of that access.
  - Dates and times it was handled.

- If you are not able to show an uninterrupted chain of custody, months or even years of hard work can be considered inadmissible in a court of law, leading to the possible release of criminals. This is why it's so critical to ensure that a proper chain of custody is maintained at all times. 
 
#### The Digital Forensic Process
 
The National Institute of Standards and Technology defines a process for performing digital forensics in [Special Publication 800-86](../1/Activities/03_Cloud_Forensics/Resources/Cloud_Forensics_Challenges.pdf) as follows:
 
- **Collection:** We must first collect the data before we can examine and analyze it. The collection phase is the springboard to the digital forensics process which includes identifying, labeling, recording, and acquiring data from sources while following procedures to preserve the integrity of the data.
 
- **Examination:** After we've collected the evidence, we begin the examination phase, which ensures that all data collected is relevant to the case. This includes forensically processing collected data and assessing and extracting data of interest while preserving the integrity of the data. This usually means working from a copy, rather than the original.
 
- **Analysis:** After we've identified all relevant evidence, we being the analysis phase by analyzing the results of the examination, using legally approved methods and techniques, to derive information that addresses the questions that inspired the collection and examination.
 
- **Reporting:** After we've analyzed all of the evidence, digital forensic investigators are required to formally report the results of the analysis, which may include describing the actions used, explaining how tools and procedures were selected, determining what other actions need to be performed, and recommended improvements to the forensic process.

#### Evidence Acquisition
 
**Evidence acquisition** is one of the most critical steps in the entire forensic process. If done improperly, it can result in evidence being missed, lost, or inadmissible in a court of law.
 
- Digital forensic data has one of two classifications: network-based or host-based.
   
   - **Network-based** data comes from data communications captured by network-based systems such as an IDS, IPS, and firewalls, in the form of a packet capture or similar.
    
     - Packet captures are useful for reconstructing events involving computer break-ins.
    
     - Logs from firewalls also provide insight into network activity.
 
   - **Host-based** data is typically found on a system that encompasses a wide variety of artifacts.
 
     - Investigations involving computer break-ins may involve the forensic examination of local file systems, programs, access to critical documents, and/or alterations to system files and directories.
 
     - Host-based examinations may involve reconstructing internet use, unauthorized activity, email recovery, and the identification of malicious files.
 
#### Creating Forensic Backups
 
During an investigation, it is important that evidence is not contaminated. As a forensic investigator, you will **image** the data. This image, not the original media, will be used for analysis. 

  - **A bit-stream image** captures all created sections of a hard drive, known as partitions, whether used or not, and all unallocated drive space that doesn’t belong to partitions. 
 
   - This method allows forensic examiners to recover deleted files and fragments of data that may exist on a hard drive.
 
   - A **local file system backup** is inadequate for forensic analysis. If you do make a copy through the file or operating system, you can see only the data that the operating system sees. This won’t capture deleted files or slack space, which . You must obtain a **bit-level copy**. 


A bit-level copy or bit-stream image copies over everything slack space, deleted files, and the regular files as well.
  
  - A local backup only copies the files that are on the system. This does not copy over slack space or deleted files.

  - Slack space is the area of a file system that indicates deleted or truncated files. 

     ![Images/bitlevel.png](Images/bitlevel.png)


Local backups of hard drives should be performed only if the machine can be taken offline. If it’s taken off of the network, then the owner of the machine cannot send remote commands to, for example, wipe the computer or lock the digital forensics experts out.
 
- A forensic backup differs from a typical local backup:

  - Typical local backups target intact files. The backup image does not include the free space and slack space on a hard drive.
 
  - Forensic backups (system image or bit-level backups)  create an exact replica of all contents contained on the entire hard drive, including slack space, free space, and deleted files.
 
   - Forensic backup images are created in the following formats: 
  
     - **Raw formats:** These formats can be created with programs such as `dd`, `ddfldd`, and `ddcdd`.
       - .bin
       - .dd
       - .img
       - .raw
 
     - **Advanced Forensic Format (AFF):** The AFF format is for disk images and related forensic metadata.
       - .AFF
       - .AFF4


#### Working with Live Systems
 
One should always use caution when working with live systems. It is possible that an attacker is waiting for the user to log back into the system to complete the attack.
 
- The primary reason for working on a live system is to capture items that will not survive a power loss, such as volatile memory, swap files, running processes, and active network connections.
 
 - Mistakes such as writing data to memory or disk can potentially destroy evidence, which is why it is critical to use forensic tools such as write blockers.
 
    - A **write blocker** is a device that allows anything connected to it to perform only read operations, therefore preventing the drive from being written to and overwriting  evidence.
 
#### File Systems
 
You may encounter the following file systems during an investigation:

   - **New Technology File System (NTFS):** Supported under Windows 10, 8, 7, Vista, XP, and NT.
 
   - **File Allocation Table (FAT):** Supported by older and newer versions of Windows.
 
   - **Apple File System (AFS):** Used by Mac OS systems.
 
   - **Fourth Extended File System (Ext4):** Used in most Linux distributions.
 
#### Overview of Storage Media

Do you know which type of storage devices they have in their computer, tablet, or phone.
 
The following will provide overviews of the physical layout of hard and solid-state devices and how data is stored. 
 
- Physical vs. Virtual Drives

    - A **virtual drive** resides on a physical drive and emulates the characteristics of a hard drive. The drive can be mounted and dismounted and data can be read and written to it.

    - Drives in general are limited by the speed at which they can receive and send information.

- Mechanical Hard Drives

    - Mechanical hard drives have very delicate moving parts that can be damaged if not handled properly.

    - Mechanical hard drives can have far larger storage capacities than other types of drives. Therefore, the imaging process can take an extremely long time when performing a bit-level copy.

    - Implications for forensics: Data can be recovered from badly damaged or comprised devices. This requires extensive knowledge of the inner workings of hard drives and how hard drives store data.

-  Flash Storage

    - Flash storage devices have no moving parts and use flash memory, allowing for quicker read and write access.

    - Flash memory or flash storage is **non-volatile**, meaning it holds data even when it's not connected to power. This technology is used in devices such as USB drives, mobile phones, cameras, and tablet computers.

- Solid-State Drives (SSD)

   - SSD storage devices use flash memory chips and have no moving parts. They also have larger storage capacity and have faster read-write access.

   -  Implications for forensics: An SSD is not a mechanical drive. One must be careful with the forensics tools used to image and recover data. The data on an SSD can be lost or wiped out in seconds.

- SD or MicroSD Cards

  - SD cards store data inside a flash memory chip, similar to solid-state devices. They are used in cell phones and smartphones.

  - Implications for forensics: It is possible to retrieve data from an SD card even if it has been reformatted or the data has been deleted. This is because data is not immediately erased, the storage is only set aside for reuse. As long as the storage space has not been used, the preexisting data is still available. This is very useful for forensics recovery.

You may encounter password-protected storage media and password-protected **firmware**. 

  - Firmware is a specific class of computer software that provides the low-level control for a device's specific hardware. 

- These situations present extreme challenges to forensic investigators and must be considered during the initial stages of the investigation.
 

### 03. Digital Forensics in the Cloud
 
 
- [Activity File: Digital Forensics in the Cloud](Activities/03_Cloud_Forensics/Unsolved/README.md)


 
### 04. Review Digital Forensics in the Cloud Activity 
 

- [Solution Guide: Digital Forensics in the Cloud](Activities/03_Cloud_Forensics/Solved/README.md)



### 05.  Overview of Digital Forensics Types and Methodology (0:15)
 
In addition to cloud-based forensics, digital forensics is a continuously evolving scientific field that incorporates many subdisciplines.
 
- **Computer forensics** is the identification, preservation, collection, analysis, and reporting of evidence acquired from computers, notebooks, and storage media. It is used to support investigations and legal proceedings. 
 
- **Disk forensics**: Involves acquiring and analyzing information stored on physical storage media, such as hard drives, smartphones, GPS systems, and removable media. This involves the recovery process of hidden data, deleted data, and slack space information.
 
- **Memory forensics**: Inspects computer memory to identify an attacker's activities on a system.
 
     - This area requires the broadest skill set. You must have knowledge of CPU architectures, operating systems and memory management, page tables, and virtual addressing, among other things.
 
     - Memory forensics is different from disk forensics in that the data investigated is stored in volatile memory, such as RAM. Unlike non-volatile memory, volatile memory refers to storage media that loses its data when rebooted. Data on hard drives does _not_ change between reboots, so it is non-volatile.
 
- **Network forensics**: The monitoring, recording, storing, and analysis of all network traffic to determine the source of security events.

  - Can you think of any tools that can be used for network forensics?

    - Network forensic tools include Wireshark, NetworkMiner, and Snort, among others.  
 
    - Investigators in this area have an excellent understanding of communication and network protocols and the tools needed to capture and analyze data.
 
- **Email forensics**: Analyzes the source and content of an email as evidence. Email forensics includes the process of identifying the sender, recipient, date, time, and original location of an email message.
 
   - Can you think of any famous email forensics cases?>
 
     **Hint:** What about the 2016 presidential election? Sony? 
  
   - Email forensics is important when proving attribution, as is often required by conspiracy and fraud cases.
 
- **Mobile device forensics**: The recovery of digital evidence from smartphones, GPS devices, SIM cards, PDAs, tablets, and game consoles.

  - For example: Cell phone forensics can be used in a distracted driving case. A forensic expert can use this data to analyze what was happening at the time of the accident.
 
- Other forensic areas include drone, internet, and malware technologies.
 

#### Digital Forensic Investigation Methodology
 
Now that we understand the importance of maintaining an accurate chain of custody, we will explore the methodology for conducting digital forensic investigations.
 
A successful digital forensics investigation is crucial for the prosecution of computer criminals.
  
- It is important to have a clearly defined, step-by-step process for collecting digital evidence to allow it to be presentable in a court of law.
 
Digital forensics has a number of investigative frameworks. They include variations of the following phases:

 1. Prepare for the Investigation
 2. Collect the Evidence / Forensic Recovery
 3. Preserve the Evidence
 4. Electronic Discovery and Analysis
 5. Present and Report


#### 1. Prepare for the Investigation

Preparation is an important first step in conducting an investigation. However, there is not always a lot of time for it.

-  As an investigator, you want to consider such things as whether the incident was remote or local, what laws are relevant, and what tools should be used (GUI or CLI).

#### 2. Collect the Evidence / Forensic Recovery

The success of the analysis phase depends on the collection phase.
 
 - During the collection phase, the investigator makes decisions about what data to collect and the best way to collect it.

 - During forensic recovery, the evidence is extracted from a device and a master copy is made.

 - How you collect the evidence determines if the evidence is admissible in court.

#### 3. Preserve the Evidence

Investigators never work on the original copy of the evidence. A read-only master is made and stored in a digital vault.

   - All processing is done on the copy.
 
   - Investigators use a write blocker to ensure the prevention of data contamination.

 A **cryptographic digest** or **hash** is made to ensure that evidence has not been altered in any way.
 
   - This hash ensures the **integrity** of the evidence throughout the investigative process.

#### 4. Electronic Discovery and Analysis

Analysis is done after data has been collected. This is sometimes referred to as **dead analysis**.

 - It's important to document everything, including:
   - Time
   - Date
   - Locations
   - Applications used
  
 - Additionally, your evidence must be reproducible. If it is not, it may be ruled as inadmissible.

#### 5. Present and Report

In this phase, investigators write an expert report that lists all tests conducted, when and how they were conducted, what was found, and the investigation's conclusions.

 * Forensics investigators may be called to testify as expert witnesses in trials or depositions.
  

### 06.  The 2012 National Gallery Case
 
By now, you should be ready to dive into an investigation. The investigation we will use for this unit revolves around the [2012 National Gallery Scenario](../1/Assets/2012_National_Gallery_DC_Attack.pdf).
 
- Over the next two days, you will be working on a case involving a planned theft at the National Gallery in Washington, DC.
 
  - The scenario is centered around an employee at the National Gallery who was planning theft and defacement.
 
  - Suspicious activity was reported to law enforcement and devices were seized, including images of hard drives and logical and physical images of mobile devices.
 
  - The seized evidence was processed by the ingest team at the Crime Laboratory.
 
  - The evidence was backed up using the Encase forensic application.

 
### 07. The 2012 National Gallery Case Activity
 

- [Activity File: 2012 National Gallery Case](Activities/07_National_Gallery/Unsolved/README.md)
- [Resource File: 2012 National Gallery Scenario PDF](Activities/07_National_Gallery/Unsolved/The_2012_National_Gallery_Scenario.pdf)
 

### 08. Review 2012 National Gallery Case Activity 

- [Solution Guide: 2012 National Gallery Case](Activities/07_National_Gallery/Solved/README.md)


### 09.  Introduction to Autopsy (0:20)
 
The last page of the 2012 National Gallery PDF describes the storage devices that were imaged as evidence. 
  
- The seized evidence included an iPhone and a tablet. These have storage devices that hold operating system data, file system data, applications, documents, pictures, videos, and music.

- We'll be looking for evidence related to the case, including:

  - SMS messages that show intent to commit a crime.
  - IP address information that indicates GPS location data.
  - Emails and email addresses that contain incriminating evidence.
 
#### Open Source Tools
 
Digital forensics relies on the expertise of examiners to analyze and interpret data retrieved by trusted forensics examination tools.
 
- Although most forensic examiners have started to use open source tools, they may not know that they can perform a complete investigation using only open source tools.
 
We will be using the [Sleuthkit Autopsy Forensic Application](https://sleuthkit.org/autopsy/docs/user-docs/4.3/index.html).
 
 - **Autopsy** is an open source graphical tool that runs on Windows, Ubuntu, Kali Linux, and OS X platforms.
 
 - We'll be using Autopsy in the Kali Linux operating system.

In order to run Autopsy properly, we'll need to ensure that the Oracle Java Development Kit is installed and updated on our Kali machine.

- Run the following in a new terminal window: `apt install -y default-jdk`. 

Ensure this finishes before running Autopsy.

Before we begin the analysis phase of the investigation, we will need to prepare the data prior to ingestion into Autopsy by generating file hashes of the digital evidence.

#### Prepare the Data
  
 
First, we'd run a **virus scan** on the image. (This takes time, so we won't be doing it in this lesson.) If any virus files are found during a virus scan, they should be documented and included in our report.
 
- Next, we'll generate **MD5** and **SHA-256** hashes for the evidence. This will ensure the integrity of the evidence. It's best practice to hash the evidence file using two different hashing algorithms. One can be used as a backup hash for the other.
 
   - Open a terminal window in Kali Linux and navigate to the `/root/corpus` directory.

   - Run the following: 

     - `md5sum tracy-phone-2012-07-15.final.E01 > tracy.original.md5log.txt`
 
     - `sha256sum tracy-phone-2012-07-15.final.E01 > tracy.original.sha256log.txt`
  
- The file has a .E01 extension, indicating it is in **Encase** image format.
 
  - Encase is a popular, commercially available digital forensic software, considered an industry standard.
 
#### The Autopsy Workflow
 
The Autopsy software has a lot of features, but in this demonstration we'll cover the following steps in the workflow:
 
  1. **Create a Case**: Create case name, investigator information, and optional information. Case information helps investigators track the progress of the case.
 
  2. **Add an Image**: Autopsy supports Raw, Encase, and Virtual Disk image formats. For this case, our evidence was imaged with Encase software, which renders a file extension of .E01.
 
  3. **Configure Ingest Modules**: For example, Email Parser, Embedded File Extractor, Android Analyzer. Ingest modules help label and categorize evidence during the ingestion process (opening the .E01 file).
 
  4. **Ingest in Progress:** The process of loading the .E01 file into Autopsy. (This will take some time.) Autopsy analyzes the file and directory structure of the iPhone image, then attempts to recreate the directory tree in its original format.
 
  5. **Manual Analysis**: Analyze data. During this stage, we  manually research the iPhone's entire file system in search of all relevant information to the case.
 
  6. **Create Timeline**: Determine times, data, and data sources. During this phase, we attempt to recreate a timeline of events that the investigation team can use to understand the actions of everyone involved.
 
  7. **Report**: Finally, we will consolidate all documented evidence records into a single document that will serve as evidence in a court of law. The format is either HTML or Excel. 
 
**Note:** First we'll complete Steps 1-3. Then, Step 4 will take some time as the file begins loading in Autopsy. 


#### Step 1. Create a Case
 
We need to create a case.
 
  1. Navigate to the following directory: `/root/autopsy-files/autopsy-4.10.0/bin`.
 
  2. Type `./autopsy` to launch the application.
 
  3. In the Welcome window, select **New Case**.
 
     ![Images/autopsy-running-4.0.png](Images/autopsy-running-4.0.png)
 
 
4. Type the **Case Name**: `2012-07-15-National-Gallery`
 
5. Type the **Base Directory**: `/root/casedata/`
 
6. For **Case Type**, select **Single-user**.
 
7. Click **Next**.
 
  ![Images/autopsy-case-information.png](Images/A-NEW-IMAGES/1.png)
 
Next, enter optional information:
 
- Enter a **Case Number** relevant to your case. For this demo, we'll use `1EZ215-P`.
  
  - Case names and numbers help investigators keep track of the hundreds or thousands of cases that may be in the system.

- We'll leave the other optional information  blank: **Name**, **Phone**, **Email**, and **Notes**.
 
- Select **Finish**. 
 
Add the evidence file and configure ingest modules.
 
#### Step 2: Add an Image
 
1. Select **Disk Image or VM File**.
 
2. Click **Next**.
 
   ![Images/autopsy-data-source.png](Images/autopsy-data-source.png)
 
3. Click **Browse** and navigate to `/root/corpus/`.
 
4. In the pop-up window, select `tracy-phone-2012-07-15-final.E01` and click **Open**.
 
5. Select a **Time zone** and click **Next**.
 
   - The investigative team may be spread across several times zones, so it's important for the case to follow a standard time zone as indicated in the case file.

   ![Images/autopsy-data-source-1.png](Images/autopsy-data-source-1.png)
 
    
#### Step 3: Configure Ingest Modules
 
Ingest modules help label and categorize evidence during the ingestion process.
 
We'll need to ingest everything for this demonstration.
 
- Click **Select All**.
 
- Click **Keyword Search** and check all of the boxes.
 
There are two ingest modules that are particularly important: **Extension Mismatch Detector** and **Keyword Search**.
 
 - Extension Mismatch Detector uses the results from the File Type Identification and flags files that have an extension not traditionally associated with the file's detected type. In other words, it ignores "known" files.
 
 - Keyword Search is used to extract the maximum amount of data from the files being indexed.
  
     * The indexing will try to extract data from supported file formats, such as text files:
    
       * Phone numbers
       * IP addresses
       * Email addresses
       * URLs
       * Credit card numbers
 
    **Note:** The more items you select, the longer the ingest process will take.
 
 ![Images/autopsy-keyword-search.png](Images/A-NEW-IMAGES/17.png)
 
- Ensure that the **Extension Manager** and **Keyword Search** boxes are checked and click **Next**.
 
#### Step 4: Ingest in Progress

 - Autopsy is now analyzing the Encase file. When this process is finished, the file is ready to be viewed and analyzed by the investigator.

This will take some time. The status is shown in the bottom-right corner of the window. You can click the progress bar to see the status.
 
   ![Images/autopsy-analyze-ingest.png](Images/autopsy-analyze-ingest.png)


#### Step 5: **Manual Analysis with Keyword Search** 
 
We can see the results of the Keyword Search ingest module as follows:
 
- Click on **Keyword Lists** in the upper-right portion of the toolbar.
 
  - We can see all of the categories that Autopsy discovered during the file ingest process, such as phone numbers, IP addresses, etc.
 
- In the dropdown, check **IP Addresses**.
 
- Click **Search**.
 
- Autopsy will highlight all of the IPs contained in the file for easy reference.
 
    ![Keyword Search](Images/A-NEW-IMAGES/16.png)

  - How can IP address information be used for this case?

    - IP addresses can reveal location information (GPS coordinates) in addition to identifying other networks or computer systems that were contacted and/or used to commit the crime.
 
#### Step 5b: Manual Analysis of SMS Messages 

 
Autopsy provides us with a way to view and read SMS messages, but first we have to set up our database.
 
- Before we make changes, we need to close our case file.
 
 - In the top-left corner, click **Case**.
 
 - In the dropdown, click **Close Case**.
 
 - If the Welcome window appears, click **Close**.
 
- Click **Tools** on the top menu bar.
 
 - In the dropdown, select **Options**.
 
    ![Keyword Search](Images/A-NEW-IMAGES/4.png)
 
 - In the **Options** window, select **Central Repository**.
 
 - In the **Central Repository Database Configuration** window, place a check mark in the **Use a Central Repository** box, then click **Configure**.
 
   ![Keyword Search](Images/A-NEW-IMAGES/5.png)
 
 - In the **Database Type** dropdown, select **SQLite**.
 
   ![Keyword Search](Images/A-NEW-IMAGES/6.png)
 
 - Click **Yes** in the **Database Does Not Exist** pop-up box, then click **OK**.
 
   ![Keyword Search](Images/A-NEW-IMAGES/7.png)
 
 - Reopen the recent case file by clicking **Case** in the upper-left corner, navigating to **Open Recent Case** and selecting `2012-07-15-National-Gallery`. 

 - Click the **Keywords Search** box in the upper-right corner.

   -  In the dropdown, enter `sms.db` and click **Search**.
 
  ![Keyword Search](Images/A-NEW-IMAGES/9.png)
 
 - You should now see the `sms.db` file populated in the **Keyword Search** (the lower-right window pane) in the **Table** tab.
 
 - Click the `sms.db` file to highlight it.
 
   - You should now be able to read SMS messages in the **Data Content** window pane in the lower-right window inside the **Indexed Text** tab.
 
   ![Keyword Search](Images/A-NEW-IMAGES/13.png)

    - What types of information can SMS messages reveal?

      - SMS messages can implicate other individuals involved in the crime. They can also reveal the objective of the crime or the motives for committing it.

#### Step 5c: Manual Analysis of Encrypted Data
  
In the **Directory Tree**, you will see an **Encryption Detected** folder under the **Extracted Content** dropdown inside the **Results** tab.

- Click on the **Encryption Detected** folder within **Extracted Content**. The `documents.zip` file will populate inside the listing window pane to the right.

- Double-click the `documents.zip` file.

   ![Images/autopsy-main.png](Images/A-NEW-IMAGES/19.png)
 
- After double-clicking the `documents.zip` file, the iPhone image's directory tree will expand inside the **Directory Tree** window, as seen below.
 
    ![Images/autopsy-main.png](Images/A-NEW-IMAGES/20.png)
 
-  Now that we have full access to the encrypted iPhone image, we can begin our investigation in search of evidence pertinent to the case.

In the next class, we will examine an iPhone image. We'll continue to learn about reporting in future classes. 

 
#### Wrap Up

Digital forensics relies on the expertise of examiners to analyze and interpret data retrieved by trusted forensics examination tools.
 
- Although most forensic examiners have adopted the use of open source tools, many of them may not know that they can perform a complete investigation using only open source tools.
 
- Autopsy is an open source, multi-platform, graphical tool that runs on Windows, Ubuntu, Kali Linux, and OS X platforms.
 
The steps we needed to complete were our first autopsy investigation were:
 
- Generate MD5 and SHA-256 hashes for the evidence in order to ensure the integrity of the evidence.
 
- Specify a case name and number to help investigators keep track of the files and their progress.
 
- Select the file type to be ingested, i.e., .E01, and specify a working directory where progress will be saved.
 
- Specify a standard time zone for the case.
 
- Configure ingest modules to help categorize, label, and organize data.
 
- Set up our central SQLite database repository to allow us to read SMS messages.
 
- Access the encrypted `documents.zip` file by expanding its directory tree for further analysis.


In the next class, we'll continue our investigation using Autopsy to analyze artifacts on iPhone images.


---

&copy; 2020 Trilogy Education Services, a 2U Inc Brand.   All Rights Reserved.




