##  8.1 Student Guide: Introduction to Networking

### Overview

Today's class is the first part of our introduction to networking.  You will learn about the client-server model and use this knowledge to assess given scenarios and identify clients, servers, requests, and responses.  You'll learn network topology and network devices in order to map your own network using the web tool Gliffy.

After studying these foundational networking concepts, the class will focus on network IP addressing, private and public IP addresses, and subnetting. The class concludes by covering similar addressing concepts as they apply to the internet, including DNS, URLs, and their security implications.

### Class Objectives

By the end of class, you will be able to:

- Identify clients, servers, requests, and responses in network communications.

- Identify network topologies and compare their advantages and disadvantages.

- Design a conceptual network made of various network and network security devices.

- Convert binary numeric representations to readable IP addresses and determine which servers the IP addresses belong to.

- Modify DNS host files to redirect the access of a website.

### Lab Environment

- You will use your local Vagrant virtual machine for today's activities. 

### Slideshow

- The lesson slides are available on Google Drive: [8.1 Slides](https://docs.google.com/presentation/d/1vCI6wTP-RJFPCp26Waxo5OtrJrl16KrMFdSWIccSwuc/edit#slide=id.g4789b2c72f_0_6)

---

### 01. Welcome and Introduction

In this lesson, we will cover the following concepts:

- Client and servers, requests, and responses

- Network topologies and design

- IP addresses and their binary and clear text representations

- DNS and DNS hijacking

### 02. Instructor Do: Intro to Networks and Network Security (0:10)

This week we'll be switching gears and focusing on one of the most important topics in cybersecurity: computer networking.

While it's pretty simple to pull up a webpage on your browser or send an email to your friends, a lot of complex technologies and systems go into making this magic happen.

A **computer network** is a multiple devices connected together to shared resources and/or services.

- **Devices**, also known as **nodes**, can be computers, laptops, mobile phones, printers, servers, etc.

- **Resources** can be webpages, emails, images, data files, etc.

- **Services** are computer programs that have a function, such as processing an online order or doing a calculation.

Computer networking is essential for the following technical roles, among others:

  - **Security Operations Center (SOC) Staff:** SOC staff commonly diagnose and troubleshoot network related security issues and attacks. Understanding network devices and network design helps them to quickly resolve and identify issues.

  -  **Network Security Engineer:** Network security engineers may work on the design of a company's network architecture to protect their organization from security risks.

  - **Penetration Tester:** Penetration testers often test for vulnerabilities in a company's network. Understanding network design and common network vulnerabilities is core knowledge for penetration testers.

A defined model is required for devices to share resources.

#### Client-Server Model

![client-server](Images/client-server.png)

The **client-server model** is a network computing model that defines how resources and services are shared across a network. Cover the following:

  - In this model, the **client** requests a resource or a service.

  - The **server** hosts the resources and services that the client is requesting.

  - The **server** will return the requested resource or execute the service requested.

For example: You go on Facebook to check your friend's vacation photos.

- Your web browser is the client requesting the resource—your friend's vacation photos.

- Facebook's web server is the server that hosts the image files of your friend's vacation photos.

- Facebook's web server is responsible for returning the requested photos back to your web browser.

This **two-way conversation** between the client and server is known as the **request and response method** of device communication. Cover the following:  

- The **request** is the process in which the client sends a message to a server asking for a resource or to run a service.

- The **response** is sent back to the client after the server receives and processes the request.

- The **response message** can be:
  - An acknowledgement of the request.

  - The resource requested.

  - An error message.

- Using the Facebook example:

    - The browser makes a **request**: "Facebook, can you please get me my friend's vacation photo?"

    - Facebook's web server provides a **response**: "Yes, here is your friend's vacation photo."

The client-server model doesn't mean a "one client, one server" relationship. Typically, servers receive resource requests from many clients.

  - For example, if other friends went on Facebook to view your friend's vacation photos, each friend would be using a different client (browser) to pull the same resource (vacation photo) from the single Facebook web server.

#### Introduction to Network Security

While computer networks provide many advantages, many network security risks and threats exist within them. As we cover new tools and concepts, you will also be introduced to relevant inherent security risks.

A **network security** is the practices and policies used to protect and monitor computer networks' resources against threats and risks.

Network security threats and risks can include:
- Unauthorized access into networks
- Denial of service  (DoS) attacks
  - For example: An attacker floods your network with traffic to make your resources unavailable.

- Eavesdropping
- Data modification
  - For example: An attacker steals your data and modifies it without your knowledge.

Network security professionals are the staff that design and implement practices and policies to protect against these threats and risks.

- As security professionals, you will often be asked to not only monitor and identify potential network security threats and risks, but also to determine the best way to mitigate them.


### 03. Network Security Activity

- [Activity File: Network Security](Activities/03_netsec/unsolved/readme.md)

### 04. Network Security Activity Review

- [Solution Guide: Network Security](Activities/03_netsec/solved/readme.md)

### 05. Instructor Do: Network Structure (0:15)

We defined a computer network as multiple devices (or nodes) connected to each other. This next section will focus on how those devices are connected.

When computer networks were first created, they were smaller, private networks initially designed to connect devices within the same room or building.  These small networks were known as local area networks.

#### Local Area Network (LAN)

A **Local area network (LAN)** as a private computer network that connects devices in smaller physical areas like a room or single building, such as a small office or home network.

![lan](Images/lan.png)

There are many advantages of using a LAN:

  - **Network speed and performance:** Since the devices are physically and geographically connected near each other, connections are significancy faster and perform better.

  - **Network security:** With security devices, a business can control what data comes in and out of their local network as well as who has access to resources.

  - **Versatility:** New network devices can be easily added or removed inside a LAN due to the proximity of the devices within the network.

Larger companies often do not have a single LAN for their organization, but instead have multiple LANs for different departments or offices within their organization.  

While these local area networks are great for sharing resources, they are limited to sharing only within their own network.

#### Wide Area Network (WAN)

As technology advanced, computer networks expanded and small networks in different locations were able to connect.

A **Wide Area Network (WAN)** is a network used to connect multiple LANs.     
- The most widely-known example of a WAN is the Internet.

The biggest advantage of using a WAN is that you are able to share or access resources across a much larger geographic area.

Disadvantages of using a WAN include:
- **Security issues**: Traffic that travels from your LAN and into a WAN needs to be encrypted and never captured.

- **Troubleshooting**: Traffic issues outside of your LAN can be challenging to troubleshoot and resolve.

Now that we know that WANs are a connection of multiple LANs, we'll look at the specific designs and techniques used to make these connections.

#### Network Topology

Computers on a network are connected using a specific design that properly serves the required performance, data flow, and other factors.

A **network topology** is the design or technique with which computers are set up on a network.

  - The topology can determine the way data flows within a local area network.
  - The topology can also impact the performance and speed of a network.

  - There are a variety of network topologies, with names based on the geometric shape of their design.

Next, we will cover various topologies, along with their advantages and disadvantages.

![ring](Images/ring.png)

**Ring**: In a ring topology, each device is connected to the next device in the chain.

- There are two sub-types of ring topologies
  - **Bidrectional**, in which the topology allows traffic to move in either direction.
  - **Unidirectional**, in which the traffic flows in a single direction.

  - In this lesson, we will be referring to the Unidirectional Ring Topology.  

 - **Advantages**
    - Simple to build.
    - Does not require a central node to manage data transmission.

    - Adding devices to the network is easy.

 - **Disadvantages**
    - If any one device goes down, the entire network is affected. In other words, every device is a **point of failure**.

    - Latency (how long it takes for data to travel between devices) is variable between devices on the network. For example, devices near one another will trade data quickly, but devices far away will experience high communication delay.

![line](Images/linear.png)

**Linear**: In a linear topology, each device is connected to the adjacent device by a two-way link. The two devices at the "ends" of the network are not connected to one another (unlike a ring topology.)

- **Advantages**
    - Adding devices to the network is easy.

- **Disadvantages**
    - A single device failure can interrupt the entire network.

    - Latency is variable between devices on the network. For example, devices near one another will trade data quickly, but devices far away will experience high communication delay.

![star](Images/star.png)

**Star**: In a star topology, all devices in the network are attached to a central node.
Devices transmit data by sending it to the central node, which then determines which other device on the network to forward it to.

  - **Advantages**
    - Communication delay is consistent between devices, since every node is the same distance from the central manager, which is ultimately responsible for forwarding data.

    - Failure of an end device doesn't endanger the entire network—the node is the only point of failure.

    - Extending the network is easy.

  - **Disadvantages**
    - The number of devices on the network is constrained by the number of connections available on the central node.

    - Can be difficult to set up if the central node is physically far away from any of the end devices.

![bus](Images/bus.png)

**Bus**: In a bus topology, every device is attached to a central data link. When a device transmits data, it sends it on the link, at which point every device on the network can receive it simultaneously.

  - **Advantages**
    - Data transmission is fast between all devices.

    - Easy to expand the network.

  - **Disadvantages**
    - Sending data to every device on a network wastes bandwidth.

    - Two devices cannot transmit data simultaneously.

![tree](Images/tree.png)  

**Tree**: A tree topology is a special type of topology in which many connected devices are arranged like the branches of a tree.  In a tree, there can be only one connection between any two connected devices.

  - **Advantages**
    - Easy to expand the network.

  - **Disadvantages**
    - If the top node is impacted, all devices below are impacted.

![fullyconnected](Images/fullyconnected.png)   

**Fully Connected**:  In a fully connected topology, every device on the network is directly connected to every other.

- **Advantages**:
    - Highly redundant: If a single link between devices fails, both devices can still communicate with the rest of the network.

    - Data transmission is point-to-point between directly connected devices. Since all devices are directly connected, transmission is fast.

- **Disadvantages**:

    - Very complicated to set up and manage.

    - The number of links in the network scales exponentially with each single device added to the network, making fully connected topologies very expensive to establish.

![mesh](Images/mesh.png)    

**Mesh**: A mesh topology is similar to a fully connected topology. However, not every device is directly connected. Rather, many of them are connected and devices on the network cooperate to find the shortest path to forward data to one another.

- The advantages and disadvantages are the same as a fully connected topology.


![hybrid](Images/hybrid.png)
**Hybrid**: A hybrid topology is any combination of the above topologies.

- For example: a linear topology with star networks attached to the endpoints.

- The advantages and disadvantages depend on the types of networks combined.

- Most modern networks are hybrid topologies.

#### Topologies and Network Security

As security professionals, understanding the different network topologies is important for the following reasons:

  - If an attacker takes down or takes control of an isolated device with no connections to any other device, only the compromised device is impacted.

  - If an attacker takes down a device that is a "point of failure," then that local area network will be impacted.

    - For example, in the ring topology, each device is a "point of failure." If one connection breaks, the whole network shuts down.

  - If an attacker takes control of a device on a topology in which that device is connected to other devices, the attacker may also be able to move from the compromised device to any other device on the network, which would have considerably more impact on the business.

Network security design focuses on building a topology that not only prevents security compromises, but also reduces the impact any compromises or failures might have.


### 06. Network Devices

We have been looking at the network devices (or nodes) like connect-the-dots. When these nodes are in their proper order, the links between machines are established and the network functions.

As we will soon learn, these nodes are actually a variety of devices, each with  complex responsibilities.

- For example, even if all devices are connected, how are resources directed correctly and efficiently from client to server and server to client?

In the following section, we will examine various network devices and the roles they play in connecting and directing the data transported across networks.

Understanding how network devices work and the connectivity function they provide are critical skills for any security professional.

- For example, if a security professional is alerted that the local network is being attacked by a flood of requests, it is crucial to understand where the attack has taken place, and what network or network security device can mitigate the attack.

Remember: LANs are private networks that have interconnected computers within a small geographic area. On the other hand, WANs are much larger networks that connect multiple LANs.

#### Primary Network Devices

We will now cover the primary network devices found on LANs and WANs.

**Routers**

- A **router** is a networking device that forwards (routes) resources to other networks.

- A router can connect two different LANs, two different WANs, or a LAN to a WAN.

- Routers are commonly used to connect your home network (a LAN) to the internet (a WAN).

**Switches**

  - A **switch** is a networking device that forwards resources within a network. In other words, switches connect devices within a LAN.

  - Switches are typically used in large businesses that have many computers.

  - Switches typically feed into routers.

  - Switches are **intelligent devices**, which means they can be programmed to direct resources to certain computers.

**Hubs**

  - A **hub** serves the exact same purpose as a switch, except it is not an intelligent device.

  - Therefore, hubs cannot be programmed. Instead, they direct a copy of the exact same resource to all computers they are connected to.

  - Hubs are less secure than switches because they direct resources to all computers, even those that do not need them.

  - Hubs are outdated and no longer commonly used.


**Bridges**

  - A **bridge** is basically a switch that only has two connections, one in and one out.

  - Bridges are often used to tie two LANs together.

**Network Interface Controller (NIC)**

  - An **NIC** is a type of computer hardware that connects a computer to a computer network.

  - An NIC is usually a circuit board or chip installed on a computer.

  - Each computer must have an NIC in order to receive or send resources.

  - NICs can either be wired or wireless.

    - **Wired**: Data is transmitted through physical wires.

    - **Wireless**: Data is transmitted with an antenna to provide wireless connections, designed primarily for WiFi.

**Modem**  

- A **modem** converts resource data into a format that the next type of connection can understand.

- In simple terms: your computer and your internet service provider speak different languages. Your computer speaks "digital" and your internet service provider speaks "analog."   

 - A modem translates between your computer and the internet service provider so they can understand each other.

- Modem is short for _modulator-demodulator_.

**Wireless Access Points (WAPs)**

- **WAPs** give wireless devices the ability to connect to a wired network.

**All-in-One Devices**

  - **All-in-one devices**  could have modems, WAPs, routers, and more all built into a single device. You may be familiar with these common household devices.

  - The advantage is that they are easy to use, as less equipment needs to be set up and maintained.

  - The disadvantage is that they are a single point of failure, and it can be difficult to troubleshoot where an issue is in a network transmission.


#### Network Security Devices

While these devices work to forward and process data at its intended destination, there are also network devices that provide **security** features to protect organization's resources.

**Firewall**

- A **firewall** is an intelligent network security device that monitors incoming and outgoing traffic based on security rules.

- Firewalls are typically placed right at the entry point of a LAN. This placement protects the confidentiality and integrity of resources within that LAN.

- There are many types of firewalls and specific firewall functionalities, which will be covered in more detail in future lessons.

**Load Balancers**

- A **load balancer**  is an intelligent network security device that distributes that incoming network traffic across multiple servers.

- A load balancer ensures no single server has to handle too much traffic.

- Load balancers help protect the availability of resources.

     - For example: If a server receives more resource requests than it can handle, it may go down or fail to handle a resource request.

- Load balancers are typically placed right after a firewall.

**Demilitarized Zone (DMZ)**

  - A **DMZ** is a smaller subnetwork, usually within a LAN.

  - DMZs add an additional layer of security to an organization's LAN, protecting secure data within the internal networks.

  - A DMZ typically has its own network security devices, such as firewalls, that attempt to detect network attacks before they access the internal networks.

We have just covered many of the network and security devices that organizations use to build their network.

#### Network Visualization

A common task for network and security professionals is to visually design a setup before purchasing, installing, and configuring a network with these devices.

Visually designing a network can assist with the following:

  - Making networks more efficient, since proximity of certain devices can reduce latency.

  - Avoiding the creation of a "single point of failure."

  - Ensuring private resources are protected from unauthorized sources.

We will use the free web tool **Gliffy** to practice designing a basic network with the following devices:

  - Two computers
  - One switch
  - One router
  - One firewall
  - One representation of the internet

#### Gliffy Demo

Open up your web browser and go to gliffy.com.

**Gliffy** is a free web tool that can be used to visually design a network.

 - It has been noted that  Gliffy may not send a confirmation email when you register to use the site.  If the drawing application does not open, try again with another email or use **draw.io**, another free web application, to complete the demonstration

To set up Gliffy, complete the following steps:

 1. Select "Free Trial" on the top right of the homepage.
 2. Sign up for the free trial by entering your information on the right side of your page
 3. Select "Start Gliffy Diagram for Free"

  ![gliffy sign-up](Images/gliffy1.png)

Select "Network Diagram" from the list of choices.

   ![gliffy diagram types](Images/gliffy2.png)

This page is where you create your Gliffy design.

Note the different features of the page:

- On the left-hand side are all the devices and shapes used to create a network design, separated by category.

- Hover your mouse over some of the devices and shapes. Their names should display.

  - Focus on the devices under the the Home and Business categories.

  - Point out several devices we've covered in class, such as routers, switches, computers, and firewalls.

    ![gliffy design page](Images/gliffy3.png)

- Add a device to the design by simply dragging and dropping them in the gridded space.

Let's start by adding the required devices for our LAN:

  - Add two computers to the grid.

  - Then, add the switch. To review, ask the class what a switch does.

     - A switch routes traffic among the computers within the LAN.

  - Since we need to connect the switch to the computers, we will use the "Connecter Tool" from the top toolbar to connect each computer to the switch.

    ![gliffy connector tool](Images/gliffy4.png)

  - Demonstrate how to drag the connecter from the device to the switch.

  - The lines signify connections.

    ![gliffy connections](Images/gliffy5.png)

Now, we will add a router that can send traffic outside of the LAN to the internet.

  - Add a router.

  - The router needs to connect to the switch, and add a connecting line between those devices.

Before we add the internet, we want to add a firewall between the router and the internet to protect our LAN.

  - Add a firewall and connect it to the router.

  - Include a representation of the internet and connect it to the firewall.

    ![gliffy connections](Images/gliffy6.png)

Finally, network and security professionals like to visualize the division between the LAN and the WAN.

  - Add a line to create a separation between the LAN and the WAN at the firewall.
    -  Select "Straight Line Tool" from the top toolbar
    
  - You can add text to the design by selecting the "A" icon at the top of the toolbar and typing your text.

  - Add text to indicate where the LAN and WAN are.

    ![gliffy final design](Images/gliffyfinal.png)

### 07. Network Devices Activity  

- [Activity File: Network Devices](Activities/09_netdev/unsolved/readme.md)


### 08. Network Devices Activity Review

- [Solution Guide: Network Devices ](Activities/09_netdev/solved/readme.md)

### 09. What's my (Network) Address? (0:15)

Computers and networks don't communicate the same way people do. They use a language called **binary**.

Everything we see on our computers, whether it's numbers, words, images, videos, or music, is all a representation of binary data.

#### Binary

At the lowest level, computers communicate with electrical signals.

  - The electrical signals have two states:  **on** and **off**.

  - Binary is a **two digit** numerical system that computers use to communicate:
    - `1` signifies an **on** signal.
    - `0` signifies an **off** signal.

  - Computers transmit these electrical signals from one computer to another, and the electrical signals get converted into binary data.

  - Once the receiving computer receives the binary data, it gets translated into a form that humans can understand.

For example: If one computer wants to transmit `1 2 3 4 5` to another computer, it can't simply transmit these five numbers as we read them, since computers only speak in binary.  

  - The computer would transmit the binary data: `00000001 00000010 00000011 00000100 00000101` which represents `1   2   3  4  5`:
      - `00000001` = 1
      - `00000010` = 2
      - `00000011` = 3
      - `00000100` = 4
      - `00000101` = 5

The conversion of this binary data into a numerical representation of  `1   2   3  4  5`  is one type of conversion called "binary to decimal." Receiving computers use other conversions as well, such as:

- Binary to ASCII:

  - ASCII is primarily used to convert binary to readable text that humans understand.
   - For example, `01101000 01101001`  represents `hi`.

- Binary to hexadecimal:

  - Hexadecimal, or hex, shortens binary data to letters and numbers.
    - For example, `11000111 00000110 10100110 11100110 11110110 01000110` represents `C7 6 A6 E6 F6 46`.

- Binary to octal:

  - Octal is another way to shorten binary data with  numbers.  
    - For example, `11000111 00000110` represents `307 6`.

  - Octal isn't as widely used as the others, but it is important to understand that binary can be converted into multiple formats.

#### Binary and Network Addresses

Binary data is relevant to this unit because it is used by networks to identify network addresses to determine where to send data.          

- A **network address** is similar to a mailing address. Without a mailing address, we wouldn't know where to send mail. Likewise, we need a specific address to send our data over networks.

- The network addresses we'll look at today are known as **IP addresses**.

An **Internet Protocol (IP) address** is a numerical network address associated with a device such as a computer, printer, router or server.

- You machine has an IP address that we can easily view them by going to [Whatsmyip.org](https://www.whatsmyip.org/).

- Check your IP address.

IP addresses are managed by a global organization known as the **Internet Assigned Numbers Authority (IANA)**.

- The IANA has sub-organizations responsible for the distribution of IP addresses.

- Two primary versions of IP addresses are distributed today. The main version is **IPv4** (IP version 4).

#### IPv4

IPv4 IP addresses are made up of four **octets** separated by decimals. These octets are the conversion of eight binary **bits** or one **byte** to standard decimal numbers.     

A **bit** is simply a single binary digit—a one or a zero.
  - A **byte** is eight bits strung together.
    - For example:
      - `1`  = one bit
      - `10110111` = one byte   

Use the following IP address as an example: `10.0.3.254`.

- "If an IP address is written as four octets separated by decimal points, why is the first part of this address  `10`?"

  - `10` is the human-readable *decimal* representation of the first binary octet.

  - `10` in binary is: `00001010`.

    - Networks communicate in binary, so they will read `0001010`. But when the number is displayed for humans to read, it is converted to `10`.

- The second octet value of `0` has a raw binary value of `00000000`.

- The third octet value of `3` has a raw binary value of `00000011`.

- The fourth octet value of `254` has a raw binary value of `11111110`.

To summarize: networks communicate in binary. When they read the IP address, they read `00001010.00000000.00000011.11111110`. That would be a little difficult for humans to read, so when displayed, it is converted to decimals, as `10.0.3.254`.

Each octet can range from zero to 255. This is because:

- The lowest value of eight bits is `00000000`, which equals `0`.

- The highest value of eight bits is `11111111`, which equals `255`.

All these conversions can be tricky. Fortunately, there is a web tool that can easily convert binary to IP and IP to binary.
  - [Browserling IP to Binary Converter](https://www.browserling.com/tools/ip-to-bin)
  - [Browserling Binary to IP Converter](https://www.browserling.com/tools/bin-to-ip)

   Simply enter the IP address or the binary representation and click "Convert."

Demonstrate each of these by converting the above IP address and binary representation on the website.

#### IPv6

There is another version of IP addresses called **IPv6** (IP version 6).

- IPv6 was created due to concern about the lack of possible addresses provided by IPv4.

- IPv6 addresses are divided into eight groups of two bytes. However, these bytes are not binary or decimal. They use letters and numbers in hexadecimal (or, hex) format. We will cover this number format in greater detail later.
  - An example of an IPv6 IP address is `2001:0db8:85a3:0000:0000:8a2e:0370:7334`.

- IPv6 has not yet been widely adopted. Many devices need to be updated before acceptting and sending traffic with IPv6. For this reason, we won't be discussing IPv6 in more detail. But it is still important to know that there are two possible IP versions.


#### Public and Private IP Addresses  

For either IP version, IP addresses are classified into two types: **private and public**.

  - **Public** IP addresses are any addresses that can be accessed over the internet.

    - **Advantages:** Public IPs are beneficial because their resources are accessible over the internet.
    - **Disadvantages:** Not all devices should be accessible over the internet, as this access potentially exposes devices to malicious actors.

    - Public IP addresses are typically assigned in **IP ranges** by an internet service provider.
      - **IP ranges** are groups of IP addresses in which the numbers are typically sequential.

        - For example, the IP range `108.0.0.1` - `108.0.0.3`  would include the IPs `108.0.0.1`, `108.0.0.2`, and `108.0.0.3`.

  - **Private** IP addresses are addresses that are not exposed to the internet. Instead, they are typically located within a LAN.

    - **Advantages:** Private IP addresses are beneficial because they aren't publicly accessible, and therefore more secure.
       - They can also be reused, as long as they are within different LANs. Private IPs can't conflict across different networks.

    - **Disadvantages:** They are not directly accessible over the public internet.

    - Private IP addresses are assigned by the network administrator of the LAN they belong to.

-  Three IPv4 ranges are saved as private addresses and are only used for private addressing:

    |Starting IP  | Ending IP       | IP Addresses Available |  
    |-------------|-----------------|------------------------|
    | 10.0.0.0    | 10.255.255.255  | 16,777,216             |  
    | 172.16.0.0  | 172.31.255.255  | 1,048,576              |
    | 192.168.0.0 | 192.168.255.255 | 65,536                 |


 All addresses not in these three ranges are considered public.


#### Subnetting

We know that an IP address is the address of a user's device. These addresses have to be assigned manually by the user or the organization that manages their local network. But how do organizations decide what IP addresses are assigned?

- Organizations are typically provided a range of IP addresses that they distribute across their departments and devices.

- Organizations often group devices together on a network for organizational and efficiency reasons.  For example: A company would group together servers designated for finance, and servers designated for marketing.

- These groups of devices are given a specific range of IP addresses.

This process of breaking up the IP address range into smaller, more specific networks for different groupings of devices is called **subnetting**.

  - For example: If a company has 100 new IP addresses to distribute, they can assign 50 to finance and 50 to marketing by subnetting the IP range they were provided.

#### Classless Inter-Domain Routing (CIDR)

To subnet, we don't have to list and assign the IP addresses in a range one by one. Instead, we use a format known as **Classless Inter-Domain Routing (CIDR)**.

![cidr](Images/cidr.png)

the CIDR format is made of two numbers: an IP address and a number indicating the range of IPs and number of IPs available.

For example: `192.243.3.0/24`:

- The **prefix**, or the number before the slash, is `192.243.3.0`. This is the IP address.

- The **suffix**, or the number after the slash, is `24`. This number indicates both the range of IPs and the number of IPs available.

This example CIDR says that everything after the first `24` bits is **variable**.

- Remember that an IP address is always four octets, or 32 bits. (Four sets of eight bits: 8 x 4 = 32)

  - In the previous example, the octets `192`, `243`, `3`, and `0` are each eight bits.

- The CIDR suffix number ranges from `0` - `32`. This number indicates how many of the IP address bits are static.

  - When we know how many bits are static, we know the remaining bits are variable.

  - These variable bits create the **range**.  

In the previous example of `192.243.3.0/24`, `24` means:

- The first 24 bits (`192.243.3`), or first three octets (3 x 8 = 24), of the IP address are a **static** number assigned to the network. These octets will not change.

- The last 8 bits (`.0`)  are **variable**. The numbers `0` - `255` are available for the host IP addresses.

  - Therefore, there are 256 available IP addresses  in the range `192.243.3.0/24`.

  - In other words, `192.243.3.0/24` means the range of IPs is` 192.243.3.0` - `192.243.3.255`

- The lower the suffix, the higher the amount of host IP addresses available to use.

  - For example: `/0` indicates roughly 4.2 billion available IP addresses, *or* every single possible IP address combination.

- The higher the suffix, the lower the amount of host IP addresses available to use.

  - For example: `/32` indicates one IP address available.

The following image illustrates the relationship between the suffix indicator and the range of IP addresses:

![CIDR-chart.png](Images/CIDR-chart.png)

While it is important to understand the concepts behind **CIDR** and **subnetting**, there are online tools you can use to easily calculate an IP address range.

- Go to the online CIDR-IP Range Calculator on your browser:  ipaddressguide.com/cidr.

- This website can easily show the range of IPs by using CIDR notation. It can also create a CIDR notation from a range of IP addresses.

  - Put in the CIDR example of: `192.243.3.0/24`

  - Note that it returns the range and count of host IP addresses as follows:

    | First IP   |Last IP   | Total Host |
    |------------|----------|------------|
    | 192.243.3.0 | 192.243.3.255 | 256  |

#### MAC Addresses

Next, we'll look at another important network address used to route traffic *within* a LAN.

- Remember that computers must have a network interface controller (NIC) in order to transmit or receive data.

- Each of these NICs has a network address called a **media access control address (MAC address)**.

Note that the MAC addresses:

- MAC addresses are connected to the network adapters on each computer and cannot be changed.

- A computer's MAC address is a string of six sets of alphanumeric characters, each separated by colons.

    - For example: `00:0a:95:9d:68:16`

- The MAC address can also indicate the manufacturer of the network device.

Switches use MAC addresses within a LAN to direct the traffic to specific devices.

  - We will cover how switches obtain the MAC Addresses of their device in the next lesson.


### 10. Network Addressing Activity

- [Activity File: Network Addressing](Activities/13_netadr/unsolved/readme.md)

### 11. Review Network Addressing Activity

- [Solution Guide: Network Addressing](Activities/13_netadr/solved/readme.md)

### 12. Instructor Do: Addresses and the Internet (0:15)

We just covered how network addresses assist with directing network traffic to its final destination.

When you visit a website on a browser, a similar process takes place.  

  - For example, if you need an image from Facebook, your computer browser (the client) needs to get the image from Facebook (the server). Facebook's IP is: `31.13.65.36`.

#### DNS

It would be challenging to remember the IP `31.13.65.36` every time we wanted to visit facebook.com.

Thankfully, we just have to remember "facebook.com," because the **Domain Name System (DNS)** translates the domain of the website (facebook.com) into an IP address (`31.13.65.36`).

- DNS is like the phone book of the internet.   

- When you visit a webpage on your browser, your browser is looking up the associated IP address of the domain behind the scenes.  

- This automated process is called the **DNS lookup**.

The DNS lookup process is "behind the scenes" and made up of several different processes:

- When a website is entered in a browser, the browser will check **DNS caches** to see if they already have the DNS translation of the domain's IP address stored.

- The caches are searched in ascending order of scope, starting at your browser's DNS cache and ending, if necessary, at the top-level domain DNS cache. We'll cover each cache in sequential order now:

Note the sequence of the DNS lookup process:

1. When a website is entered into a browser, the browser first checks its own table of DNS translation to see if the translation already exists for that particular website.  

    - If there is no record of that domain in the browser's DNS cache, it will move through the following steps until it finds the translation.

2. Next, it will look in the operating system's DNS cache. The operating system's DNS cache is stored in a file called the **hosts file**.
    - In **Windows**, it is located at: `C:\Windows\System32\drivers\etc\hosts`.

    - In **Linux**, it is located at: `/etc/hosts/`.

3. If the domain is not in the host file on the operating system, the next place checked is the DNS cache of the **Internet Service Provider (ISP)**.

4. If the domain is not there, the final place checked is the DNS cache of your **top-level domain (TLD)**.

    - The TLD is the highest point of the internet's Domain Name System hierarchy.

    - TLDs are the built into the name of the website—they are the word following the dot (".").

    - Examples of TLDs are: com ,net ,org, and biz.

    - The TLD of facebook.com is _com_.

   - TLDs are responsible holding all the DNS translations for all domains within their TLD.

5. Finally, the TLD will pass the DNS translation back to the ISP, then to operating system hosts file, then to the browser.

 All of these systems will now store that DNS translation in their own **DNS cache**, meaning the next time this domain is looked up, this lookup process won't be necessary.

#### URLs   

A domain is the website we access for resources and the resources we're requesting are typically at a specific location within that domain.

   - For example: If we are viewing a picture from Facebook, the picture likely isn't located at the URL facebook.com.  It is likely at a specific location, such as facebook.com/photos/catpicture.jpg.

The resource is located in the **URL (Uniform Resource Locator)**. Cover the following about URLs:

- A URL is the full address of a resource on the internet.

- Like file structures, URLs have a specific syntax indicating where to find the specific resource being requested.

   The syntax is: `scheme://subdomain.domain.TLD/path/filename`

  - For example: `https://www.facebook.com/photos/catpicture.jpg`

    - **https**: (_Hyper Text Transfer Protocol_) Scheme indicating a file on the internet.  

    - **www**: Subdomain of facebook.com.

    - **facebook**: Primary domain.

    - **.com**: TLD, or top-level domain.

    - **/photos/**: Path where the resource is located.

    - **catpicture.jpg**: Resource or file being requested.

- Web server will use the URL to determine the exact location of the resource being requested, then return this resource back to the client—the browser.

#### DNS, URLs and Security

While DNS and URLs provide many benefits for accessing resources from the internet, these technologies also introduce security risks.

- Remind the class that DNS caches indicate where to request the resources from, based on the domain being accessed.

- Therefore, if a hacker is able to manipulate the DNS cache, they can trick and exploit a user's request by returning a domain or resource that was not originally requested.

  - For example:

    - A hacker owns a malicious site located at the IP `137.74.187.102`.

    - The hacker accesses your hosts file DNS cache and updates a record that makes browser requests for facebook.com go instead to `137.74.187.102`.

    - Now, every time you go to facebook.com, you are redirected to the hacker's malicious website.

This process is called **DNS Hijacking**, a type of network attack that exploits DNS vulnerabilities to divert web traffic away from legitimate servers and towards fake or malicious servers.

#### DNS Hijacking Demonstration

Now we'll walk through the process of DNS Hijacking using the previous example.

- Open up your terminal.

On the Linux server, the host's file is located at `/etc/hosts`.

- Run `cd /etc`

- Run `ls` to confirm there is a file called `hosts`.

Open up the file using `nano`.

  - Run `sudo nano hosts`.

The `hosts` file is where the DNS translation occurs on your Linux operating system.

- The syntax for adding in a record: `[IP address]       [domain]`

- Add in the following record: `137.74.187.102  krebsonsecurity.com`

  ![DNSspoof](Images/dns_spoof.png)

Save the file:
  - Hit `ctrl+x` then `y` then press enter.

All browser requests for krebsonsecurity.com on your operating system will now be directed to the IP address
  `137.74.187.102`.

- Pull up a browser and entering krebsonsecurity.com. The page displayed obviously isn't krebsonsecurity.com.

   **Note**: You may have to override a few browser warnings.

    ![DNSspoof2](Images/dns_spoof2.png)

Security professionals must understand how DNS Hijacking works.

- For example: A hacker can use this attack to direct users to malicious phishing sites that look exactly like real sites, but are designed to capture users' credentials.  

- The hosts file can also be edited for non-malicious purposes, such as preventing users from accessing certain social media sites.


### 13. DNS Hijacking Activity

- [Activity File: DNS Hijacking](Activities/16_netdns/unsolved/readme.md)

### 14. Review DNS Hijacking Activity

- [Solution Guide: DNS Hijacking](Activities/16_netdns/solved/readme.md)

---

### Copyright

Trilogy Education Services © 2020. All Rights Reserved.
