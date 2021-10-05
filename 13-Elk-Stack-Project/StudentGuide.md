## 13.1-13.3 Student Guide: ELK Stack Project Week

### Overview

This week, you will set up a cloud monitoring system by configuring an ELK stack server.

### Week Objectives

You will use the following skills and knowledge to complete the following project steps:

- Deploying containers using Ansible and Docker.
- Deploying Filebeat using Ansible.
- Deploying the ELK stack on a server.
- Diagramming networks and creating a README.

**Note:** While you must complete your projects individually, you can work through problems together, and should ask instructional staff for help if you get stuck.

**Important:** Due to Azure Free account limitations, you can only utilize 4vCPUs per region in Azure. Because of this, we will need to create a _new_ vNet in another region for our ELK server.

### Lab Environment

You will continue using your personal Azure account and build upon your existing Azure VMs. You will **not** be using your cyberxsecurity accounts.

### Additional Resources
- [Ansible Documentation](https://docs.ansible.com/ansible/latest/modules/modules_by_category.html)
- [`elk-docker` Documentation](https://elk-docker.readthedocs.io/#Elasticsearch-logstash-kibana-elk-docker-image-documentation)
- [Virtual Memory Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html)
- ELK Server URL: http://your-IP:5601/app/kibana#/home?_g=()
- [Docker Commands Cheatsheet](https://phoenixnap.com/kb/list-of-docker-commands-cheat-sheet)

### Slideshow

The slideshow to this week is located on Google Drive here: [ELK Stack Project Week (13) Slides](https://docs.google.com/presentation/d/1b0jbp5L_ws2iCFuOSnU7BfoXb6oSiWccqmwXKk8yJ0w/edit#slide=id.g4789b2c72f_0_6)


---


## Day 1: Configuring an ELK Server

Lectures cover the following:

  - Give an overview of the ELK stack and how it performs network security monitoring. This overview will also give you valuable context for why you're configuring and deploying these tools during the week.

  - Provide the project overview as well as suggested milestones for each day. 

  - Due to Azure Free account limitations, you can only utilize 4vCPUs per region in Azure. Therefore, we will need to create a new vNet in another region for our ELK server.

  - By the end of the project, we will have an ELK server deployed and receiving logs from all three web VMs created in the previous cloud weeks.

Activities involve the following: 

  - Create a new vNet in Azure in a different region, within the same resource group.
  - Create a peer-to-peer network connection between your vNets.
  - Create a new VM in the new vNet that has 2vCPUs and a minimum of 4GiB of memory.
  - Add the new VM to Ansible’s `hosts` file in your provisioner VM.
  - Create an Ansible playbook that installs Docker and configures an ELK container.
  - Run the playbook to launch the container.
  - Restrict access to the ELK VM.

<details> <summary> <b> Click here to view the 13.1 Student Guide. </b> </summary>

---

### 01. Project Overview  

The purpose of project week is to provide an opportunity to combine everything you've learned in order to create and deploy a live security solution.

- This boot camp includes three projects in total. In the next two, you will expand on the work they started this week, developing a portfolio reflective of your increasingly sophisticated skill-set.

This week, you will deploy an ELK monitoring stack within your virtual networks. This will allow you to monitor the performance of your web server that is running DVWA.

- In particular, the ELK stack allows analysts to:

  - Easily collect logs from multiple machines into a single database.

  - Quickly execute complex searches, such as: _Find the 12 internal IP addresses that sent the most HTTP traffic to my gateway between 4 a.m. and 8 a.m. in April 2019._

  - Build graphs, charts, and other visualizations from network data.

At the end of the week, you will have a fully functional monitoring solution, live on the cloud. This will be a major achievement for a few reasons:

- Deploying, configuring, and using an ELK stack is a common task for network engineers, SOC analysts, and other security professionals. Completing this project will be proof of your skills, which you can present to hiring managers.

- The ELK stack is very commonly used in production. You will likely work for organizations that use either ELK or Splunk, which is covered later in the course. Experience with both is a great addition to a job application.

- You can expand this network with additional machines on your own time to generate a lot of interesting log information. This sort of independent research is useful for learning, and hiring managers love to see it.

The amount that you have learned in order to complete this project, including systems administration, configuration as code, virtualization, and cloud deployment, is substantial. 

Congratulations on having made it this far!

#### Project Deliverables

As you work through the project, you will develop the following "deliverables" that you can take to job interviews:

- **Network diagram**: This document is an architecture diagram describing the topology of your network.

- **Technical brief**: Answers to a series of questions explaining the important features of the suite, completed after deploying the stack.

- **GitHub repository**: Instructions are provided in this week's homework as to how to set up a Github account. After completing the project, you will save your work to a database, called a Git repository, along with an in-depth description of the project. This will make it easy for you to redeploy your work in the future, as well as share it with others.

You will also be prompted to talk about your projects as they pertain to specific cybersecurity domains. 

#### Today's Class

The rest of today's class will proceed as follows:

- Introduction to ELK: An overview of the technologies that make up the ELK stack and its capabilities.

- Project Work: Working hands-on through the project steps to develop your networks.

You can complete this project even if you don't have all four VMs set up. Missing VMs can be added after the project tasks are completed. 


### 02. Instructor Do: Introduction to ELK

Before deploying an ELK Stack, let's cover what the stack can do and how it work. You should be familiar with ELK from previous units:

- ELK is an acronym. Each letter stands for the name of a different open-source technology:

  - **Elasticsearch**: Search and analytics engine.

  - **Logstash**: Server‑side data processing pipeline that sends data to Elasticsearch.

  - **Kibana**: Tool for visualizing Elasticsearch data with charts and graphs.

- ELK started with Elasticsearch. Elasticsearch is a powerful tool for security teams because it was initially designed to handle any kind of information. This means that logs and arbitrary file formats, such as PCAPs, can be easily stored and saved.

- After Elasticsearch became popular for logging, Logstash was added to make it easier to save logs from different machines into the Elasticsearch database. It also processes logs before saving them, to ensure that data from multiple sources has the same format before it is added to the database.

- Since Elasticsearch can store so much data, analysts often use visualizations to better understand the data at a glance. Kibana is designed easily visualize massive amounts of data in Elasticsearch. It is also well known for its complex dashboards.

In summary:

- Elasticsearch is a special database for storing log data.

- Logstash is a tool that makes it easy to collect logs from any machine.

- Kibana allows analysts to easily visualize your data in complex ways.

Together, these three tools provide security specialists with everything they need to monitor traffic in any network.

#### The Beats Family

The ELK stack works by storing log data in Elasticsearch with the help of Logstash.

Traditionally, administrators would configure servers to collect logs using a built-in tool, like `auditd` or `syslog`. They would then configure Logstash to send these logs to Elasticsearch.

- While functional, this approach is not ideal because it requires administrators to collect all of the data reported by tools like `syslog`, even if they only need a small portion of it.

- For example, administrators often need to monitor changes to specific files, such as `/etc/passwd`, or track specific information, such as a machine's uptime. In cases like this, it is wasteful to collect all of the machine's log data in order to only inspect a fraction of it.

ELK addressed this issue by adding an additional tool to its data collection suite called **Beats**.

- Beats are special-purpose data collection modules. Rather than collecting all of a machine's log data, Beats allow you to collect only the very specific pieces you are interested in.

ELK officially supports eight Beats. You will use two of them in this project:

- **Filebeat** collects data about the file system.

- **Metricbeat** collects machine metrics, such as uptime.

  - A **metric** is simply a measurement about an aspect of a system that tells analysts how "healthy" it is. 
  
  - Common metrics include:
    
    - **CPU usage**: The heavier the load on a machine's CPU, the more likely it is to fail. Analysts often receive alerts when CPU usage gets too high.

    - **Uptime**: Uptime is a measure of how long a machine has been on. Servers are generally expected to be available for a certain percentage of the time, so analysts typically track uptime to ensure your deployments meet service-level agreements (SLAs).

- In other words, Metricbeat makes it easy to collect specific information about the machines in the network. Filebeat enables analysts to monitor files for suspicious changes.

You can find documentation about the other Beats at the official Elastic.co site: [Getting Started with Beats](https://www.elastic.co/guide/en/beats/libbeat/current/getting-started.html).

### 03. Instructor Do: Project Overview

Now it's time to begin deploying it. In this section, we will:

- Describe exactly what you will be building.

- Lay out the milestones that you should complete each day.

After that, you will spend the rest of the class configuring and deploying your ELK stack.

#### Project Setup

The goal of this project is to add an instance of the ELK stack to a new virtual network in another region in Azure and configure your 3 Web VMs to send logs to it.

Make sure you are logged into your personal Azure accounts and not the cyberxsecurity accountr. You will be using the VMs you created during the week on cloud security.

Since you will be building off of that week, let's take a moment to review the network architecture built in that unit.

This network contains:

  ![Cloud Network](Images/Finished-Cloud-Diagram.png)

- A gateway. This is the jump box configured during the cloud security week.

- Three additional virtual machines, one of which is used to configure the others, and two of which function as load-balanced web servers.

Due to Azure Free account limitations, you can only utilize 4vCPUs per region in Azure. Therefore, we will need to create a new vNet in another region in Azure for our ELK server.

- By the end of the project, we will have an ELK server deployed and receiving logs from web machines in the first vNet.

:warning: **Important:** Azure may run out of available VMs for you to create a particular region. If this happens, you will need to do one of two things:

1. You can open a support ticket with Azure support using [these instructions](https://docs.microsoft.com/en-us/azure/azure-portal/supportability/how-to-create-azure-support-request). Azure support is generally very quick to resolve issues.

2. You can create another vNet in another region and attempt to create the ELK sever in that region.

    - In order to set this up, you will perform the following steps:

      1. Create a new vNet in a new region (but same resource group).
      2. Create a peer-to-peer network connection between your two vNets.
      3. Create a new VM within the new network that has a minimum of 4GiB of memory, 8GiB is preferred.
      4. Download and configure an ELK stack Docker container on the new VM.
      5. Install Metricbeat and Filebeat on the web-DVWA-VMs in your first vNet.

You will use Ansible to automate each configuration step.

At the end of the project, you will be able to use Kibana to view dashboards visualizing the activity of your first vNet.

![Cloud Network with ELK](Images/finished-elk-diagram.png)

Note: You will install an ELK container on the new VM, rather than setting up each individual application separately.

:warning: **Important:** The VM for the ELK server **must** have at least 4GiB of memory for the ELK container to run properly. Azure has VM options that have `3.5 GiB` of memory, but **do not use them**. They will not properly run the ELK container because they do not have enough memory.

- If a VM that has 4GiB of memory is not available, the ELK VM will need to be deployed in a different region that has a VM with 4GiB available.

- Before containers, we would not have been able to do this. We would have had to separately configure an Elasticsearch database, a Logstash server, and a Kibana server, wire them together, and then integrate them into the existing network. This would require at least three VMs, and definitely many more in a production deployment.

- Instead, now we can leverage Docker to install and configure everything all at once.

Remember that you took a similar approach when creating an Ansible control node within the network. You installed an Ansible container rather than installing Ansible directly. This project uses the same simplifying principle, but to even greater effect.

#### Project Milestones

The suggested milestones for each day are the following:

- **Day 1** (Today): Configure the ELK server.

- **Day 2**: Complete installation of Filebeat and Metricbeat.

- **Day 3**: Finish any outstanding tasks from Day 2 and spend the majority of class finishing your network diagrams and answering questions in the brief.

For the remainder of the day, we will work on configuring an ELK server within your virtual network.

#### Troubleshooting Theory


Before we dive into the work today, let's briefly enforce the importance of independent troubleshooting as a means to not only solve the problem at hand, but also learn more about the technology that you are working with.  

Specifically, we will review the [Split-Half Search](https://www.peachpit.com/articles/article.aspx?p=420908&seqNum=3), an effective troubleshooting methodology that can be applied to _any_ technical issue to find a solution quickly.

The general procedure states that you should remove half of the variables that could be causing a problem and then re-test. 

  - If the issue is resolved, you know that your problem resides in the variables that you removed. 
  
  - If the problem is still present you know your problem resides in the variables that you did not remove. 
  
  - Next, take the set of variables where you know the problem resides. Remove half of them again and retest. Repeat this process until you find the problem.

In the context of this project, removing half of your variables could mean:

- Logging into the ELK server and running the commands from your Ansible script manually.

	- This removes your Ansible script from the equation and you can determine if the problem is with your Ansible Script, or the problem is on the ELK Server.

	- You can manually launch the ELK container with: `sudo docker start elk` or (if the container doesn't exist yet); `sudo docker run -p 5601:5601 -p 9200:9200 -p 5044:5044 -it --name elk sebp/elk:761`

- Downloading and running a different container on the ELK server.

	- This removes the ELK container from the equation and you can determine if the issue may be with Docker or it may be with the ELK container.

- Removing half of the commands of your Ansible script (or just comment them out).

	- This removes half of the commands you are trying to run and you can see which part of the script is failing.

Another effective strategy is to change only one thing before your retest. This is especially helpful when troubleshooting code. If you change several things before you re-test, you will not know if any one of those things has helped the situation or made it worse.


#### Day 1 References

- For more information about ELK, visit [Elastic: The Elastic Stack](https://www.elastic.co/elastic-stack).

- For more information about Filebeat, visit [Elastic: Filebeat](https://www.elastic.co/beats/filebeat).

- To set up the ELK stack, we will be using a Docker container. Documentation can be found at [elk-docker.io](https://elk-docker.readthedocs.io/).

- For more information about peer networking in Azure, visit [Global vNet Peering](https://azure.microsoft.com/en-ca/blog/global-vnet-peering-now-generally-available/)

- If Microsoft Support is needed, visist [How to open a support ticket](https://docs.microsoft.com/en-us/azure/azure-portal/supportability/how-to-create-azure-support-request)

- [Split-Half Search](https://www.peachpit.com/articles/article.aspx?p=420908&seqNum=3)

### 04.  ELK Installation

- [Day 1 Activity File: ELK Installation](Activities/Stu_Day_1/Unsolved/ReadMe.md) 

- [Day 1 Resources](Activities/Stu_Day_1/Unsolved/Resources/)

---

### End of Day 1 Milestone

In this class, you:

- Deployed a new VM on your virtual network.
- Created an Ansible play to install and configure an ELK instance.
- Restricted access to the new server.

Completing these steps required you to leverage your systems administration, virtualization, cloud, and automation skills. This is an impressive set of tools to have in your toolkit!

</details>

---

## Day 2: Filebeat

Lectures cover the following

- Provide a brief overview of Filebeat.

Activities involve the following: 

- Navigate to the ELK server’s GUI to view Filebeat installation instructions.
- Create a Filebeat configuration file.
- Create an Ansible playbook that copies this configuration file to the DVWA VMs and then installs Filebeat.
- Run the playbook to install Filebeat.
- Confirm that the ELK Stack is receiving logs.
- Use the same method to install Metricbeat.

<details>
<summary> <b> Click here to view the 13.2 Student Guide. </b> </summary>

---

### 01. Instructor Do: Filebeat Overview

In the previous class, we installed the ELK server. Now it's time to install data collection tools called **Beats**. 

Before  working on the activity, let's review the following about Filebeat: 

- Filebeat helps generate and organize log files to send to Logstash and Elasticsearch. Specifically, it logs information about the file system, including which files have changed and when. 

- Filebeat is often used to collect log files from very specific files, such as those generated by Apache, Microsoft Azure tools, the Nginx web server, and MySQL databases.

- Since Filebeat is built to collect data about specific files on remote machines, it must be installed on the VMs you want to monitor.

If you have not completed all Day 1 activities, you should finish them before continuing onto the Filebeat installation. 

### 02. Day 2 Filebeat Installation

- [Day 2 Activity File: Filebeat and Metricbeat Installation](Activities/Stu_Day_2/Unsolved/ReadMe.md) 

- [Day 2 Resources](Activities/Stu_Day_2/Unsolved/Resources/)

 **Note:** The Resources folder includes an `ansible.cfg` file. You will not need to do anything with this file. It's included in case a you accidentally edit or delete your configuration file.


### End of Day 2 Milestone

If your ELK server is receiving logs, congratulations! You've successfully deployed a live, functional ELK stack and now have plays that can:

- Install and launch Docker containers on a host machine.
- Configure and deploy an ELK server.
- Install Filebeat and Metricbeat on any Debian-flavored Linux server.

Even more significant is that you've done all of this through automation with Ansible. Now you can recreate exactly the same setup in minutes.

</details>

---

## Day 3: Exploration, Diagramming and Documentation

Lectures will cover:

  -  Kibana's features and demonstration of how to navigate datasets.
  -  Supplemental assignment in which you answer interview-style questions about your project. 

Activities involve the following: 

  - Finalize the network diagram you began during the cloud security week.
  - Draft a README explaining what you've built.
  - Craft interview response questions.


<details>
<summary> <b> Click here to view the 13.3 Student Guide. </b> </summary>

---

### 01. Day 3 Overview

Today's lesson will proceed as follows:

- An instructor demo on navigating logs using Kibana, followed by a Kibana activity and review.
- A brief overview of the supplemental interview questions that you can answer. 

- You can use the rest of the day to complete your project.

  - If you need more time installing Filebeat on your DVWA machines, you can continue this work.

  - If you finished the Filebeat installation, you can work on a network diagram and project README.

  - You will also have the opportunity to answer questions about the project as it relates to different cybersecurity domains.


### 02. Exploring Kibana

Now that we have a working instance of Kibana, we will learn a bit about how to use it.

- Companies use tools like Kibana to research events that have happened on your network.

- Any attack leaves a trace that can be followed and investigated using logs. As well,
registrars sometimes don't take down clever malicious domains, leaving businesses to index and defend against them themselves.

Kibana is an interface to such data, and allows cyber professionals to gain insight from a lots of data that otherwise would be un manageable.

The following walkthrough provides a quick overview of using Kibana.

#### Kibana Walkthrough

1. - Start by importing Kibana's Sample Web Logs data.

      - You can import it by clicking **Try our sample data**.

     ![](Images/kibana/Welcome.png)

    - You can also import it from the homepage by clicking on **Load a data set and a Kibana dashboard** under **Add sample data**.

     ![](Images/kibana/add-data.png)

    - Click **Add Data** under the **Sample Web Logs** data pane.

      ![](Images/kibana/sampledata.png)


   -  Click **View Data** to pull up the dashboard.

2. A brief overview of the interface, starting with the time dropdown in the top right of the screen:

   - Kibana categorizes everything based on timestamps.

    - Click on the drop down and show that there are several predefined options that can be chosen: Today, Last 7 days, Last 24 hours, etc.
        
   ![](Images/kibana/Change-time.png)
      
   - Overview of data panes:

        - **Unique Visitors**: Unique visitors to the website for the time frame specified.
      - **Source Country**: Web traffic by country.
      - **Visitors by OS**: The kind of OS visitors are using. 
      - **Response Codes Over Time**: HTTP response codes 200, 404 and 503.
      - **Unique Visitors vs. Average Bytes**: The number of visitors and the amount of data they use.
      - **File Type Scatter Plot**: A graph showing the types of files that were accessed.
      - **Host, Visits and Bytes Table**: A table showing the kinds of files that were accessed.
      - **Heatmap**: Hours of the day that are most active by country.
      - **Source and Destination Sankey Chart**: Connections that have been made by country. The thicker the line, the more data was transferred between machines.
      - **Unique Visitors by Country**: Countries the traffic is originating from.

  - These panes are interactive and can help filter data.

  -  Click on the United States inside Unique Visitors by Country to see how the panes change to reflect only the data that originated from the United States.

  ![](Images/kibana/us.png)

3. We can further dive into this data using Kibana's Discover page.

    - Locate the hamburger dropdown menu at the top-left of the page and choose the **Discover** option under the **Kibana** heading.

      ![](Images/kibana/Discover.png)

    - We can now look at interactions between clients and the server with more detail.

    - Each item listed is not a single packet, but represents the entire interaction between a specific client and the server (i.e. it represents _many_ network packets that were exchanged).

    - Click the expansion arrow next to the first interaction and show the resulting table of information.

      ![](Images/kibana/discover2.png)

    - We can see things like source and destination IPs, the amount of bytes exchanged, the geo coordinates of the source traffic, and much more.

      ![](Images/kibana/discover3.png)

   - This data is still filtered by traffic originating from the United States.

4. Click the hamburger dropdown menu again and return to the **Dashboard** option listed under **Kibana**.

    ![](Images/kibana/Discover.png)

   - Remove the `geo.src: US` filter that is applied to the data by clicking on the small **x** near the filter tab.

     ![](Images/kibana/filter.png)

   - In the next activity, we will have the opportunity to explore these logs further and gain more insight from the traffic.


### 03.  Activity: Exploring Kibana 


  - [Activity File: Exploring Kibana](Activities/Stu_Day_3/Exploring-Kibana/Unsolved.md)
  - [Solution Guide: Exploring Kibana](Activities/Stu_Day_3/Exploring-Kibana/Solved.md)


### 04. Project Communication - Documenting, Diagramming, and Discussing

You have produced an impressive deliverable that you can display to potential employers and your professional network. Today you will have the opportunity to develop network diagrams and README documentation. You will also add the project to a GitHub repository for homework. 

Another important piece of presenting this project in a professional manner is verbally communicating all the skills and knowledge they've gained so far.  

In this section, we will introduce an optional section of the project in which you will answer mock interview responses. Responses should demonstrate a robust understanding of your work and the ability to relate it to various security domains. 

#### Mock Interview Questions Overview

- The work you did on this first project covers a wide range of topics including cloud, network security, and logging and monitoring.
- When networking and talking to potential employers, you should be able to reference the work done on this project to answer specific interview questions or demonstrate your skills within a specific domain. This section will teach you how to do this.
- First we'll explain a general structure for answering common technical interview questions. We will then show you examples that use this structure, and also use specific examples from Project 1.
- Then it's your turn. First you will choose a domain that you're interested in pursuing as a career. For this project, you will choose from the following domains:

  - Network security
  - Cloud security
  - Logging and monitoring
- Within each domain, we have provided a set of interview questions.  For each question, you will think about specific tasks completed in Project 1 that you can use to answer the question.

For this section, you will:

- Select a question.

- Write a one-page response that answers the question using specific examples from your work on Project 1. Your response should flow and read like a presentation while still keeping the general structure of the technical question response guidelines. 

It's okay if students are unsure which domain you want to focus on. You can either choose the one you're most comfortable discussing, or complete the tasks in two or all three domains.

- In Projects 2 and 3, you will complete similar extension activities. Offensive and defensive security will be included as additional domains in these later projects.

- Additionally, during Career Prep week, we will discuss how you can adapt your interview responses for Demo Day networking.

#### Responding to Technical Questions

In this section, we will walk through the process of answering technical interview questions.  

Interviewers frequently ask open-ended questions like: "How you would secure access to a cloud network?"

- Answering such questions can feel difficult at first. The question is indirect, with multiple possible answers. 
- But you have valuable experience that you can draw on to provide a compelling response.

We'll begin by walking through the structure of a good response. Then we will look at some example answers that incorporate specific details from Project 1.

#### Structure of Good Responses

- Interviewers do not want you to immediately supply a direct answer, even if it's the right one. 
- The point of open-ended questions is to see if you can explain your thought process and rationale.

- Good responses do more than just provide an answer. They also demonstrate that you truly understand the question and solution.

Regardless of the specific question, good responses all do the following:

- Restate the problem.
- Provide a concrete example scenario.
- Explain the solution requirements.
- Explain the solution details.
- Identify advantages and disadvantages of the solution. 

Ensuring all of your responses to open-ended technical questions include these components will help you prove to interviewers your competency and expertise. Next, we will look at a specific interview question and apply this framework using examples from Project 1.

#### Sample Question #1

Here is a sample question from the Cloud Security domain:

**Question**: How would you control access to a cloud network?

Let’s walk through the steps to answer this question:

1. **Restate the Problem**
   - When restating the question in your own words, add additional details to demonstrate you understand what is being asked and why.

    - Example: "It's important that organizations control access to a cloud network, especially since it has resources that only the engineering team should be able to access. Following the principle of least privilege, you want to make sure engineers can access it easily, but no one else can." 


2. **Provide a Concrete Example Scenario**

   - Use the parameters of the question to create an example scenario of the problem you just restated. This makes the problem easier to talk through and further demonstrates your experience with the topic. 

   - Use your class experience to form scenarios. All your assignments are legitimate evidence of your technical background and experience, and can be referenced in your answers to open-ended questions.

   - Example: "In Project 1 of my cybersecurity bootcamp, we solved an almost identical problem. In that project, we deployed a virtual network containing several VMs to Azure, which only we and our instructional team were supposed to be able to access. Just as an organization would limit cloud network access to only engineers, we had to implement remote access controls limiting access to only a handful of authorized individuals."


3. **Explain the Solution Requirements**


    - Before explaining the details of your solution, explain the high-level actions you took at each step and what they accomplished.


    - Example: "After deploying the network, I first had to configure a network security group around the whole subnet. This blocked traffic from all IP addresses, except for mine, my partners', and my instructors'. This NSG allowed inbound access to only one machine on the internal network, the jump box.
    
       Then, I configured additional NSGs on the VMs within the subnet. This allowed connections only between the jump box and other local IP addresses.


       Finally, I forced the use of SSH keys to eliminate vulnerability to password-based brute-force."


    - Note: This example lists three high-level steps, including tools used and what each step accomplished. It does not explain exactly how you implemented each step.


4. **Identify Advantages and Disadvantages** 

* Point out why your solution works in general. Then acknowledge any potential shortcomings and how you would address them.


    - Example:  "This solution worked well for my project because it ensured only the selected users had access. However, it is difficult to maintain and scale because it requires updating the NSG every time a new user requires access to the network. In addition, securely using SSH keys can be tricky in the long run. An alternative solution addressing these shortcomings would be implementing a VPN gateway to the private network. This would allow us to manage and monitor users more safely and scalably."


    - Note: This reflection further demonstrates to the interviewer that you understand not only the problem and solution, but also the tradeoffs of your solution.


5. **Explain the Solution Details**

    - Now that you explained the high-level steps and reflected on the pros and cons, explain the specifics of how you would implement the solution. The examples below are shortened for brevity, but real answers would typically include considerably more detail.

    - Example: "To configure access controls around the entire subnet, I created an NSG with the following ruleset: […] These rules allow access to the jump box from only the specified IP addresses specified.

       Then, to configure access controls within the subnet, I created NSGs with the following ruleset: […] These rules allow the VMs within the network to communicate only with each other and with the jump box.

       To force the use of SSH keys, I modified the following configurations in the VMs on the network: [...] This ensures that password brute-force attacks will always fail."

<details>
<summary> (Optional) Answering Sample Question #2 </summary>
<br>

**Question**: What is the most difficult networking bug you've ever faced, and how did you resolve it?

  - Note: This question is a bit different from the one before. For instance, there is no explicit problem to restate. Fortunately, the same response structure will still work, with a few small tweaks.


1. **Restate the Problem** 

   - This question does not pose a specific problem for you to explore. Instead, it requires that you select and explore one of your own debugging experiences. 

2. **Provide a Concrete Example Scenario**

   Select a debugging experience and explain the problem that you had to debug. Do this by answering the following questions:

   - In which part of the project did you encounter the most annoying bug? Consider the following high-level tasks:

     - Creating Azure VM deployments.
     - Configuring VMs with Ansible.
     - Installing and Running ELK with Docker.
     - Implementing access controls.


    - What were you trying to implement when you encountered this bug? If applicable, what error message did you get? For example: installing Docker, deploying infrastructure.
    
    - What did you expect to happen? What would have happened if everything went well?
    
    - What actually happened? What went wrong that you didn't expect?


    - Based on the above error output, how did you determine your first debugging steps?
    
    - What did you discover as you performed your debugging steps?
    
    - Which technique was successful?


3. **Solution Requirements and Details**

   - In addition to explaining which debugging step was successful, elaborate on the following:
   
     - How did you ultimately implement the solution so that you could move on?
   
     - How did you verify that your solution worked?
   
     - Based on your solution, what was broken in the first place?
   
     - Why did your solution work?


4. **Explain Advantages and Disadvantages**

   - Finally, consider the following:

     - Why was this a good solution for the circumstances?

     - Does the same solution work for larger projects? Why or why not?

     - If a different solution is necessary, what would you use instead?

</details>

### 05. Project Communication and Further Exploration

- [Activity File: Diagramming the Network](Activities/Stu_Day_3/Diagram/Unsolved.md)
- [Activity File: Completing the README](Activities/Stu_Day_3/Create-Readme/Unsolved.md)
- [Activity File: Interview Questions](Activities/Stu_Day_3/Interview/Unsolved.md)
- [Activity File: Kibana Continued](Activities/Stu_Day_3/Kibana-Continued/Unsolved.md)


### 06. Turn Off Machines and Wrap-Up

After you complete your diagrams, finish your README, and/or present your work, make sure you **turn off** your virtual machines.

- Navigate to `portal.azure.com`.
- Search for and select **Virtual machines**.
- Select every VM in the list.
- Click **Stop**. This will ensure you're never charged for any of the machines you used in the project.


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
