## Azure and Ansible Reference Sheet

This "cheatsheet" contains examples of every Ansible command you will need during the project week. Keep this open as you work through the challenges.

### Ansible Playbooks and Modules
Recall that an Ansible module is an Ansible "command." In other words, modules are what you use to implement tasks in a playbook.

  ```yaml
  # 'Command' is a module used for running bash commands
  - name: Print a silly message
    command: echo 'this is a silly message'
  ```

A playbook is composed of many tasks, each of which may use a different module.

Ansible has hundreds of modules, all of which are thoroughly documented on the [Ansible Module Index](https://docs.ansible.com/ansible/latest/modules/modules_by_category.html). However, this documentation is difficult to use if you don't know which module to use. This cheatsheet will:
- Review everything you need to know about playbooks to complete the project.
- Provide examples of every Ansible module you will need this week.

  - Since these examples demonstrate each module and option you will need this week, you should not _need_ to use the official documentation. But, know that the documentation includes a lot more usage examples.

---

### Ansible Directory 
Let's briefly review the files and folders in `/etc/ansible`.

Recall that `/etc/ansible` contains all the files you use to provision other machines. This includes:
- The inventory file.
- The Ansible configuration file.
- Playbooks.
- Any files you need to upload to the target machines.

The directory structure typically looks like:

```bash
/etc/
  ansible/
    ansible.cfg
    hosts
    my_first_playbook.yml
    my_second_playbook.yml
    files/
      picture_to_upload.png
      configuration_file_to_upload.ini
```

We will review each file.

#### Ansible Inventory File: `hosts`
The inventory file, usually named `hosts`, contains the IP addresses of the machines you want to configure with Ansible.

IP addresses are usually put in **groups**. Groups allow you to refer to an entire set of related machines at once.

```ini
# IP addresses of DVWA machines
[webservers]
172.168.0.1
172.168.0.2

# A group with one member
[timemachines]
192.168.0.15
```

This `hosts` file contains two groups: `[webservers]` and `[timemachines]`. Note that a group doesn't have to contain more than one machine, as is the case with `timemachines`. 

You will use group names in playbooks to specify which machines to run the playbook on. See below for an example of such usage.

```yaml
---
- name: Example Playbook
  hosts: webservers
  tasks:
    - name: Install curl
      apt:
        force_update_apt: yes
        name: curl
        state: present
```

This playbook installs `curl` on all the IP addresses in the `[webservers]` group: `172.168.0.1` and `172.168.0.2`.

The project requires you to create a group called `elkservers` in your `hosts` file, which will contain only a single IP address.

#### Ansible Configuration File: `ansible.cfg`
The `ansible.cfg` contains configuration details such as which SSH key to use, whether to encrypt communications, and which user to connect as.

The `ansible.cfg` is important, but you will rarely need to update it, and not at all for this project.

#### Playbooks and Tasks
**Tasks** are specific configuration settings that Ansible must implement, such as installing `curl` in the example above.

A playbook is a collection of tasks, written in YAML. A playbook is usually responsible for a single high-level task, such as installing and configuring a web or file server.

In this project, you will create three playbooks:
- `install-elk.yml`: This will install the ELK stack on the VM in your `elkservers` group.
- `install-filebeat.yml`: This will install Filebeat on your `webservers` group.
- `install-metricbeat.yml`: This will install Metricbeat on your `webservers` group.

See the **Ansible Playbooks** section for hints on how to create these different playbooks.

#### Files for Upload
Configuring a machine sometimes requires you to place files on it. Ansible can move files to a target VM with the `copy` module, and you will typically save any files you need to copy to the VM in the `/etc/ansible/files` directory.

When you get to the Filebeat and Metricbeat installation challenges, see the notes in **Ansible Modules: `copy`** for thorough instructions on how to use the `files` directory.

---

### Ansible Playbooks
This section will discuss how to create, format, and maintain playbooks. 

#### Creating and Formatting Playbooks
Recall that: 
- A task is a specific configuration you implement using Ansible, such as installing `curl` in the example above. 
- A playbook is a collection of tasks that, when performed together, completely provision a machine.

Playbooks are written as YAML files. All playbooks have two "parts," as illustrated below:

  ```yaml
    ---
    # PART 1: Header
    - name: Configure Time Machines
      hosts: timemachines
      remote_user: traveler
      become: True
      tasks:

    # PART 2: Task List
      - name: Install Warp Drive
        apt:
          force_update_apt: yes
          state: present
          name: warp-drive
  ```

Note the following:
- Part 1 is the **header**. The header contains information that Ansible uses to determine which machines to connect to, and how to log in.

- Part 2 is the **task list**. This is simply the series of tasks that Ansible must complete to configure the machine.

The section below on **Ansible Modules** provides more details about implementing Part 2. 

In this section, we will focus on Part 1: the header.

- The header specifies the following fields:
  - `---`
    - These three dashes are required by YAML.
  - `hosts`
    - This field specifies which machines to run the playbook on.
      - For example, `hosts: timemachines` tells Ansible to run this playbook on the IP addresses in the `timemachines` group.
    - See above for an example of a `hosts` file that includes a `timemachines` group.
  - `name`
    - This field is technically optional, but you should always include it. It describes the purpose of the playbook.
  - `remote_user`
    - This field tells Ansible which username to use to log into the target VM.
      - For example, `remote_user: traveler` directs Ansible to log into the target VM using the username `traveler`.
  - `become: true`
    - Setting `become: true` forces Ansible to run all commands with `root` privileges. 
    - This helps ensure Ansible does not encounter errors when installing packages, creating users, or performing other administrative tasks.

Most of the settings in the header are self-explanatory. But you should pay attention to the following:
- `become: True` should be included in all of your playbooks.
- `hosts`
  - Your playbook to install the ELK server should have `hosts: elkservers`.
  - Your playbook to install Filebeat and Metricbeat should have `hosts: webservers`.
- `remote_user`
  - Your playbook to install the ELK server must have `remote_user: elk`.
  - Your playbook to install Filebeat and Metricbeat _does not_ need a `remote_user` option. You can remove it.

The project instructions will direct you to these notes when you begin writing your playbooks.


#### Maintaining Multiple Playbooks
Often, configuring a machine requires several high-level steps. For example, configuring a web server involves:
- Installing and configuring the server.
- Restricting permissions of local user accounts.
- Configuring firewall rules and network-level access controls.

It's possible to include all of these steps in a single playbook. However, that playbook would get very long very quickly, making it hard to maintain, test, and reuse.

Instead of creating a single, massive playbook, best practice is to create one playbook for each high-level task. For instance, you might configure a web server with the following playbooks:
- `install-apache.yml`
- `harden-permissions.yml`
- `configure-firewall.yml`

Having three different playbooks makes it easy to maintain each playbook independently. For example, this allows you to alter the Apache configuration without modifying the file that manages firewall rules.

#### Creating Multiple Playbooks for the Project
This project requires you to create the following playbooks:
- `install-elk.yml`
- `install-filebeat.yml`
- `install-metricbeat.yml`

Each will contain tasks specific to its purpose. For example, `install-filebeat` will _only_ download and install Filebeat, and nothing else.

The main advantage of this is that it makes it easy to run each playbook on a different group of machines. Refer to the snippets below to get started with your own playbooks.

 ```yaml
 ---
 # Header for `install-elk.yml`
 - name: Install and Configure ELK Stack
   hosts: elkserver
   remote_user: elk
   become: True
 ```

 ```yaml
 ---
 # Header for `install-filebeat.yml`
 - name: Install Filebeat
   hosts: webservers
   become: True
 ```

 ```yaml
 ---
 # Header for `install-metricbeat.yml`
 # This is identical to the header for `install-filebeat.yml`
 - name: Install Filebeat
   hosts: webservers
   become: True
 ```
---

### Ansible Modules
This section includes explanations and examples of every Ansible module required to complete the project.

#### `apt` Module
The `apt` module is used to install new packages. It is equivalent to using `apt-get` on the command line.

For example:
```yaml
- name: Install curl
  apt:
    force_update_apt: yes
    state: present
    name: curl
```

- `force_update_apt: yes`: Forces Ansible to run `apt-get update` before installing packages.
- `state: present`: Directs Ansible to install `curl` if it isn't already installed.
- `name: curl`: Instructs Ansible to install the tool named `curl`.

Thus, this command is equivalent to running the following familiar commands on the shell:

  ```bash
  $ apt-get update
  $ apt-get install curl
  ```

Find documentation at: [Ansible `apt` Module](https://docs.ansible.com/ansible/latest/modules/apt_module.html#apt-module).

#### `copy` Module
The `copy` module is used to upload files from the machine running Ansible, to the target.

![DIAGRAM: Ansible Machine w/ Arrow to Target VM. Label Arrow w/ File name (`example.txt`) and a file emoji/icon.]() 

For example:
  ```yaml
  - name: Copy homepage to web server
    copy:
      src: ./files/index.html
      dest: /var/www/index.html
  ```

This example copies the file `./files/index.html` from the machine running Ansible _to_ `/var/www/index.html` on the machine being configured.

- `src`: Path to the file to upload.
- `dest`: Path where you want to upload the file on the target VM.

**Note:** It is best practice to place all files you want to upload in `/etc/ansible/files`.

Your directory structure should look like this:

```bash
/etc/
  ansible/
    ansible.cfg
    hosts
    your_playbook.yml
    files/
      example_file.txt
```

If you use this organization, the `src` path you pass to the `copy` module will always be `./files/[file_name]`.

**Hints:** On Day 2, you will be required to create playbooks that install Filebeat and Metricbeat. Part of the installation process involves configuring the Filebeat and Metricbeat services.

When you configure services on the command line, the standard workflow is:
- SSH into the machine you want to configure.
- Open the default configuration file in a text editor.
- Make the appropriate changes.
- Save the file.

With Ansible, however, the workflow is different. Since you cannot use a text editor to alter a file with Ansible during the provisioning process, you must create the final configuration file on your Ansible VM, then _upload_ it to the target VM during provisioning.

You will need to use this technique when you write your Filebeat and Metricbeat playbooks. Specifically, you will need to:
- Copy the provided `filebeat.yml` and `metricbeat.yml` into your Ansible VM's `/etc/ansible/files` directory.
- Edit the lines that say `changeme` and/or `TODO` as indicated.

These are the default configuration files for Filebeat and Metricbeat, respectively. 

To finish these files, you must make sure that all of the IP addresses and passwords they contain align with the actual IP addresses and passwords of the machines on your network. After that, these files will be complete. 

To use these files, your playbooks must copy them onto the target VMs. For example, the `install-filebeat.yml` playbook must contain a `copy` task like the one below:

```yaml
- name: Copy filebeat.yml
  copy:
    src: ./files/filebeat.yml
    dest: /path/to/destination
```

- The correct `dest` path is specified in the installation instructions. The task for `install-metricbeat.yml` will look almost identical.

Find documentation at: [Ansible `copy` Module](https://docs.ansible.com/ansible/latest/modules/copy_module.html#copy-module).

#### `command` Module
The `command` module is used to run bash commands on the target machine.

While Ansible is used in order to avoid running bash, it's sometimes necessary for highly specific tasks that Ansible doesn't have a module for.

Using the `command` module is straightforward.

For example:
```yaml
- name: Print a silly message
  command: echo 'this is a silly message'
```
- You can use any bash command you want in place of `echo`.

Find documentation at: [Ansible `command` Module](https://docs.ansible.com/ansible/latest/modules/command_module.html#command-module).

#### `docker_container` Module
The `docker_container` module is used to easily download, launch, and manage Docker containers.

Docker containers can be started and managed on the command line with tools like `docker ps`, `docker attach`, etc. However, Ansible provides modules for dealing with Docker directly.

You'll only need one for this project: `docker_container`.

For example:
```yaml
- name: Install and Launch DVWA Container
  docker_container:
    name: dvwa
    image: citizenstig/dvwa
    state: started
    ports:
      - 2001:2001
      - 72:82
      - 8080:80
```

As this example indicates, the `docker_container` module allows you to download, start, and name a container, as well as specify its port mappings, all in a single task.

- `name`: The container's hostname. If you were to run `docker_container`, you would see the name `dvwa` in the far-right column.
- `image`: The image to download from Docker Hub.
- `state: started`: Directs Ansible to launch the container after downloading it.
- `ports`: Specifies how to forward ports from the container to the host: `host:container`.  
  - For example, `8080:80` means _forward the container's port `80` to the host's port `8080`_.
  - Docker port mappings might feel confusing, and you don't need to understand them in detail to complete the project, as the correct configurations are provided for you.

**Hints:** You will need to include a `docker_container` statement in the `install-elk.yml` playbook. Your task will look very similar to the above, but the following will be different:
- The `name` attribute
- The `image` name
- The `port` mappings

All of these are provided in the project instructions. It is, however, up to you to translate them to the proper task.

Find documentation at [Ansible `docker_container` Module](https://docs.ansible.com/ansible/latest/modules/docker_container_module.html#docker-container-module).

#### `pip` Module
The `pip` module is a lot like the `apt` module. 

While you use `apt` to install official Linux packages, `pip` is used to install tools specifically for Python developers. You aren't writing any Python in this project, but many tools are written in Python.

You don't need to be familiar with `pip`, or even what Python packages are. All you need to know is:
- Many tools are written in Python, including some of Docker.
- `pip` is used to install Python tools.
- The `pip` Ansible module will use whichever version of `pip` you have installed.

For example:
```yaml
- name: Install a Python tool called "requests"
  pip:
    name: requests
    state: present
```

Note that this is almost identical to the syntax of the `apt` module.

The project requires that you use `pip` to install `docker`. The snippet you write will be almost identical to the example above.

- `name`: The name of the Python package (tool) to install.
- `state: present`: Instructs Ansible to install the package.

Find documentation at: [Ansible `pip` Module](https://docs.ansible.com/ansible/latest/modules/pip_module.html#pip-module).

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  