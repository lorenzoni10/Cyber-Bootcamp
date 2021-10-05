## Homework: GitHub Fundamentals and Project 13 Submission

In this assignment, you will review the concepts and procedures of git and GitHub. You will create a repository that will serve as the location where you can store any scripts, diagrams or other documentation that you have worked on throughout this course. Additionally you will be tasked with uploading the README file, network diagram, and other associated files that you have created during the ELK Stack project. Uploading these files will serve as the official submission of your project. 

Once you have completed the assignemnt, you will submit your repository link to BCS. 



### Background

To understand GitHub, you need to know the basics of **version control**.

- Version control is a system that allows users to save all versions of a file while working on it. It's like adding an undo function to any document or file. You create save points as you work, which you can revert to at any time.

- **Git** is the most popular software used for version control. It runs on your local computer and allows you create save points (known as **commits**) for your documents. 

- You can use Git to manage any directory and track every item inside that directory. At any point, you can revert the Git directory (known as a **repository**) to a previous commit. 

GitHub is a website that allows you to sync your local Git repository with a repository in the cloud. This allows you to save your work to the cloud, share your work with others, and easily collaborate on a project. 

- Other users can access your online GitHub repository and sync their own changes. They can also make a copy of your repository to create an entirely new project based on your original project. This is known as **forking**.

In this activity, you will:

- Create a new, empty Github repository and sync it to your local machine. 

- Once your repository is up, you will add all of your Ansible scripts, Bash scripts, and network diagrams to the repository, and sync it again with the cloud. 

- When everything is synced, you will update the GitHub README file, which will explain each of the items in the repo, and display a network diagram. You will then have a GitHub repository to present to future employers. 

You will also use your GitHub account for other activities in the course.

### Required Files 

- **Ansible YAML** scripts from the Cloud Security Unit.

    - Gather all of your Ansible YAML scripts from your Ansible container on your jump box.

    - Copy and paste these into new documents on your local machine.

- **Bash scripts** from the Linux System Administration Unit.

    - Gather all of your system configuration scripts you created during the Linux weeks.

- Network diagrams from the Cloud Security and Networking Units. 

    - Gather all of the network diagrams you created during the weeks on cloud security and networking. 

### Your Goals

1. Create a GitHub repository for all of your files. 

2. Copy all of your files into the repository and create a README explaining the repository.

### Topics Covered in this Assignment

The topics covered in this homework assignment are:

- Creating a new GitHub repository.
- Syncing a local repository.
- Creating a README file.
- [Markdown](https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet)
- The following commands:
    - `git pull`
    - `git add`
    - `git commit -m`
    - `git push origin --set-upstream <-branch->`

### Submission 

You will submit this assignment by submitting the link of your Github repository onto BCS. 

---

### Instructions

#### Part 1: Setting Up Your Repo 

1. Create your GitHub repository.
    - Go to [github.com](https://github.com/) and sign up for GitHub.
    - Confirm your email address.
    - Click **Create a Repository**.
    - Name your repository and give it a short description.
    - Check the box for **Initialize this repository with a README**.
    - Click **Create Repository**. 

2. Download your repository. 

    - Click the green **Clone or Download** button on the right side.
    - Copy the link.
    - Go to your command line and run the command: `git clone https://github.com/your-username/yourlink.git`
        - Enter your GitHub username and password to complete the download.


#### Part 2: Adding Files

3. Once you have the repository downloaded, copy your scripts and diagrams into it. 

    - Create folders for `Linux`, `Ansible` and `Diagrams`.

    - Copy your scripts and diagrams to the appropriate folder.

    - **Note**: Do not upload your Project files just yet. There are separate instructions for those in Part 3. 

4. Sync your local and remote repositories. 

    - In your terminal, make sure you're located in the top directory of your repo.  

    - Run `git add .` to specify that you want to sync _all_ the items and directories that you just added to your repo. This command stages your files for a commit. 

    - Run the command `git commit -m "First commit"` to confirm the commit and add a note describing it ("First commit").  

     - Run `git push` to finalize the sync.

    - Go to github.com and confirm your content is there.


#### Part 3: Adding Your Project Files

5. Add the README file and associated files that you created during Day 3 of the project week. 

    - Click on the `README.md` file in your GitHub repo.
    - Click on the small pencil that reads **Edit this file** on hover.
    - Copy and paste the `README.md` file you wrote during class. 
    - Make any desired changes and click **Commit Changes** at the bottom of the screen.

     **Note:** READMEs are written in Markdown. This [Markdown Cheatsheet](https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet) has more information about writing in Markdown. 



<details><summary> Instructions for creating your README.md</summary>
<br> 

The following is a duplicate of the instructions from the Day 3 README activity. If needed, refer to these instruction to complete your README. 

#### Instructions

README formats vary across projects, but you can use this template to get started: [README.zip](../Resources/README.zip).

- Download and unzip the template. Inside, you'll find a file called `README.md`, which contains the template. Much of the contents are provided, but you will need to fill in the TODO fields.

- You will also notice an `Images` folder. A few TODO items require you to place screenshots in your README. Place your screenshots in the `Images` folder, and update the README template with the appropriate file name.  

For homework, you will create a GitHub repository where you will save your project files and this README. Your repository will include:
- Your network diagram.
- A description of the deployment.
- Tables specifying access policies and network addresses.
- A description of the investigation you completed using Kibana. 
- Usage instructions.

This professional-level repository will prove you have the knowledge and communication skills that hiring managers are looking for.

While it may feel less substantial than the project itself, one of the most important skills a cybersecurity professional can have is the ability to articulate what they know. The README is an important capstone to the project and will serve as a compelling portfolio item for prospective employers.

</details>

     
<details><summary> Instructions for creating your Network Diagram</summary>
<br> 

The following is a duplicate of the instructions from the Project Week Networking Diagram activity. If needed, refer to these instruction to complete your network diagram.

#### Instructions

Use [Gliffy](https://www.gliffy.com) or [Draw.io](https://draw.io) to diagram your network. Make sure your diagram includes:

- **VNet**: Create a box that contains the machines on your virtual network. Within your VNet, diagram the following:
  - Jump box and other VMs.
  - Ansible control node.
  - Specify which VM hosts the DVWA containers.
  - Specify which VM hosts ELK stack containers.

- **Security group**: Create a box around your VNet to indicate the security group, and use a text field to specify the rules you have in place.

- **Access from the internet**: Add an icon representing the public internet and indicate how it connects to VMs in your VNet.

Use a text field to label each VM with the following information:
- Network (IP) address
- Operating system and version
- Installed containers
- Exposed ports
- Allowed IP addresses

</details>

Check your repo for any errors or typos. You now have a GitHub repository that is ready to present and share with the world. 

Once your repository is complete, submit the link on BCS. 
    
--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.



