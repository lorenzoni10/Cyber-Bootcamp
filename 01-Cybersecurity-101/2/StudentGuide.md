## 1.2 Student Guide: Attacking and Defending

### Overview
Today, you will assess attack and defense strategies of a vulnerable web login. Once you have completed these two activities, you will spend the rest of the day installing and setting up your virtual machine environments.

### Class Objectives

By the end of class, you will be able to:

- List different types of user, web, server, and database cybersecurity attacks.

- Identify risk mitigation plan frameworks for user, web, server, and database cybersecurity attacks.

- Set up a virtual machine lab environment that you will use throughout the course.

### Slideshow 

The lesson slides are available on Google Drive here: [1.2 Slides](https://docs.google.com/presentation/d/1sVnwH-LouyXe_citL2uHDPKdx8QKKbKB3eEJbkUDIss/edit#slide=id.g4f80a3047b_0_990)

---

### 01. Welcome and Overview

In the previous class:

- You were introduced to the structure of the course and the staff who will be supporting you. We also covered the rise of cybersecurity, the boot camp's course overview, and the technical infrastructures we will use to complete labs. Finally, we introduced the fundamental cybersecurity concept of the CIA triad. 

Using the slideshow, briefly review threat assessment and risk mitigation, and the CIA triad. 

- Briefly discuss how cybersecurity focuses on two primary concepts:

  - **Threat assessment**: The structured process of identifying the threats posed to a group or system.

  - **Risk mitigation**: The systematic reduction of the impact and likely occurrence of a negative event.

- Why do we use the word "mitigation" and not "eradication"? 

  - We cannot eradicate all risks. Since cybersecurity is an ever-evolving landscape, new threats show up every day. Also, business needs and budgetary constraints often limit the ability to implement cybersecurity best practices. So we must do our best to mitigate.

#### Today's Topics

Today's class will continue with assessing risk and mitigating threats by evaluating specific attacks and vulnerabilities of users, web applications, servers and databases. In short, we will be thinking about ways to attack and defend pillars of organizations in order to access and protect valuable information. 

**In the first half of today's class**, you will have the opportunity to think like offensive and defensive cybersecurity professionals evaluating the attacks and defenses of levels of information within a company.  

- To assess threats and mitigate risks, we need to look at each component of an organization, and understand how malicious actors can exploit weaknesses within the organization and damage the stakeholders' finances, reputations, and well-being. 

**In the second half of class**, you will set up VirtualBox and Vagrant—two programs needed to run VMs on local machines. You should have a basic familiarity with the need for VMs from our technical overview in the first day of class. Today, we will dive into more detailed installation instructions. 

- As the first technical activity of the course, you may may have trouble and need assistance from instructional staff. And you may need to do some troubleshooting yourselves. 

- Troubleshooting is the process of problem solving. 

- In this course, troubleshooting will often involve ensuring that our virtual machines and lab services are running smoothly. 

While troubleshooting doesn’t sound quite as exciting as attacking and defending information systems, it is just as important a skill. 

- Whether you are a penetration tester, system administrator, SOC analyst, network admin, or IT help desk associate, you will most likely have to troubleshoot technology on a regular basis.

- Troubleshooting will be a common theme throughout this course, and we'll be doing it alongside various activities, such as tinkering with scripts, configuring Azure Lab setups, and navigating access controls. Just as troubleshooting is necessary in the professional environment, it will be necessary in this learning environment. 

Troubleshooting may include trial and error, googling, or asking a classmate for help. 

- Remember that every time we have to look something up is an opportunity to expand our knowledge. **Googling** is a common task for IT professionals. It allows us to quickly reference, confirm, and discover information about tasks or issues that we are unfamiliar with. 

- The more you work through the problems you encounter during your daily activities and setups, the more robust your knowledge will be for solving any issue you encounter in the professional world. Hiring managers consider this problem-solving mentality a valuable quality. 


### 02. Introducing Security Challenge #1 - Attacking the Wall

We will now work on two security challenges related to assessing threats and mitigating risks. 

In this first activity, we will look at various **attack** strategies that hackers can use to penetrate insecure logins. 

- This exercise should force you to think creatively about all the ways a system can be penetrated, from user attacks to physical break ins. 

### 03. Activity: Security Challenge #1 - Attacking the Wall

- [Activity File: Security Challenge #1 - Attacking the Wall](Activities/03_Attacking_the_Wall/Unsolved/Readme.md)

### 04.  Activity Review: Security Challenge #1 - Attacking the Wall


### 05. Security Challenge #2 - Defending the Wall


- [Activity File: Security Challenge #2 - Defending the Wall](Activities/05_Defending_the_Wall/Unsolved/Readme.md)

### 06.  Activity Review: Security Challenge #2 - Defending the Wall

---

### 08. Break

---

### 09. Introduction to Virtual Machines Setup

For the rest of the day we will be setting up the virtual environment we will use for the majority of future class activities. 

- During the first two weeks, the in-class activities will be mostly big-picture security thinking and conceptual exercises.  

- Starting in Week 3, we will be completing hands-on technical activities.

- To complete these activities, you will need access to virtual machines and virtual networks. You will use these tools to practice attacking and securing systems.

#### What is a Virtual Machine?

- To most people, a computer means a desktop or laptop. These are the common **physical machines** we use in everyday life.

- Physical machines, also known as bare metal machines, are physical computers that have hardware components used to run a variety of tasks.

- Physical machines contain many computer parts, or hardware, that make them run. The monitor, graphics card, and the hard drive are all examples of hardware.

It's possible to write a software program that simulates a whole computer.

In other words, it's possible to simply run an application that acts like a completely different physical computer!

  - These software versions of physical computers are called **virtual machines (VMs)**.

  - We can use a single physical machine to run multiple virtual machines, effectively turning one computer into many.

Virtual machines have many advantages over physical machines:

  - They are easy and inexpensive (often free) to set up and run.

  - They can be easily distributed. In this class, we will be distributing VMs so that each student is running the exact same setup.

  - As mentioned earlier, multiple VMs can be placed on a single physical machine.

Physical machines' main advantage over virtual machines is that they are typically more efficient because they access the hardware components directly.

For our first use of VMs in this class, we will run the command line on a specific virtual machine known as **Ubuntu VM**. 

### 10. Local Virtual Machine Setup

**A Note on Troubleshooting**: The upcoming VM setup and maintenance of VMs may require troubleshooting. It is important to understand that for cybersecurity and network professionals, troubleshooting is an essential part of the job. 

- The following document contains instructions on downloading the virtual machine as well as how to update the virtual machine in the future:

  - [Using Vagrant](https://docs.google.com/document/d/1Grxbagm-2jg22LiatDHzLDpJOsOl5JWJ9gl00TtiX6k/edit)


For the remainder of today’s class, we’ll focus on the three-step installation process illustrated in the Using Vagrant doc:

1. Accessing the command line and downloading VirtualBox and Vagrant. 
2. Downloading the virtual machine using Vagrant files and scripts.
3. Accessing your virtual machine. 

| :warning: **Important** :warning: |
|:-:|
| Please read  [this document](https://docs.google.com/document/d/1MKcMYmsiDWMMDZ2rL3KcY41Rq2RulxrYxxV2MYgblC4/edit#heading=h.6saygus57a1j) for thorough step-by-step instructions on downloading and installing your virtual machine. This document also contains more detailed instructions on the Vagrant commands you’ll need to update your virtual machine, as well as common troubleshooting issues. |


### Step 1: Accessing the command line and downloading VirtualBox and Vagrant.

To run virtual machines, we first need to make sure that we have the following tools installed:

- **Git Bash** for Windows users and **Terminal** for Mac users.
  - Windows users will need to install Git Bash.
  - Mac users will already have Terminal installed by default. They can open it  by clicking on the magnifying glass icon at the top right corner of their computer, typing "Terminal" and pressing Enter.
  
- **VirtualBox**: A virtualization tool we will use to run various lab activities. VirtualBox allows us to run different operating systems on our local machines.

- **Vagrant**: A tool we'll use to build and set up these virtual environments. Vagrant will allow us to run scripts that install virtual machines, which will then be run using VirtualBox. We will run these scripts using Git Bash or Terminal. 

Prework provided resources for you to begin this installation process on your own. If you have not yet completed these installs, you should complete them now. 

### Step 2: Downloading the virtual machine using Vagrant files and scripts. 

Now that we have our tools installed, we need to download the following files:

- `vagrant-linux.sh`: A script file that ensures your virtual machine is installed properly on your computer.

- Vagrantfile: Configuration file that configures and defines your virtual machine setup. In our case, when executed via the `vagrant-linux.sh` script, the Vagrantfile will configure the custom Linux Ubuntu machine that you are using. (The file name of the Vagrantfile is `Vagrantfile`, with no extension.) 

File links are below: 

- [vagrant-linux.sh File](VM-Setup/vagrant-linux.sh)
- [Vagrantfile File](VM-Setup/Vagrantfile)

Once you have these files on your local machines, we'll work through Part 2 of the [Using Vagrant](https://docs.google.com/document/d/1Grxbagm-2jg22LiatDHzLDpJOsOl5JWJ9gl00TtiX6k/edit) document.

- If you get stuck, reference the following video tutorial: 
  - [YouTube: Vagrant VM Installation](https://www.youtube.com/watch?v=9p__oadGyo4&feature=youtu.be)

It may take up to a half hour for the virtual machine to download, so use this time to troubleshoot. 

Once you have set up your virtual machine using `vagrant-linux.sh` and the Vagrantfile, move on to the next section. 

### Step 3: Accessing the virtual machine.

In later units, we will start our virtual machine using Git Bash and Terminal. For now, we will access it via the graphical user interface, or GUI.

Using the same document, move through Part 3:

- [Using Vagrant](https://docs.google.com/document/d/1Grxbagm-2jg22LiatDHzLDpJOsOl5JWJ9gl00TtiX6k/edit)

Wrap up the installation and setup process by confirming that you've completed the following: 

1. Accessed the command line and downloaded VirtualBox and Vagrant.  
2. Downloaded the virtual machine using Vagrant files and scripts.
3. Accessed the virtual machine.

### 11. Virtual Machine Setup and Maintenance

The Using Vagrant document also contains a long section on virtual machine maintenance. This requires downloading the latest version of the virtual machine, as they are constantly being improved and updated. 

Complete the following commands in sequence to update your virtual machine with the most recent changes:

1.  `vagrant box update` to get the most recently updated virtual machine. This might take several minutes or longer, depending on your internet connection. 

2. `vagrant destroy` within the directories where your Vagrantfiles are installed, to ensure that the virtual machines are stopped and all associated files are removed.

3. `vagrant up` to launch the new version of the virtual machine.

4. `vagrant box prune` (optional) afterwards, to delete all old, unused versions of the virtual machine.

If you're still struggling with installs, meet with the instructional staff during office hours. 

You will use these Vagrant virtual machines for the first time in Unit 3, Day 1. 


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.    
