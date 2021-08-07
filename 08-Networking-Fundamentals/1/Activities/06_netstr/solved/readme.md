
## Solution Guide: Network Structure

The goal of this exercise was to get more comfortable identifying the security risks introduced or prevented by various network topologies.

Completing this activity required:

 - Identifying the topology of each office.

 - Determining the impact to each office network if the hacker took down the network connection from their computer.

 - Evaluating whether the impact would be more or less severe if the hacker was actually at a different computer in each office.

--- 
Sydney Office

- Topology: **Ring**

- If the hacker disrupts the network traffic from the assumed location, the whole office will be impacted.  In ring topologies, all the traffic flows in one direction. If one device loses connectivity, it impacts all the other devices.

- No matter which device the hacker is at, the entire Sydney office will go down if the hacker takes down their device's network.



Paris Office

- Topology: **Star**

- If the hacker disrupts the network traffic from the assumed location, only the hacker's device will be impacted. The office's network will still work because the central device connecting all the other devices is still operational. 

- The only device that would have a large impact is the central node of the star, which would take down the whole office if the hacker disrupted the network traffic.

Bogotá Office


- Topology: **Tree**

- If the hacker disrupts the network traffic from their assumed location, the whole office will be impacted because the hacker is the top node in the tree.

- If the hacker disrupted the network traffic from a device below the indicated location, it would only impact the devices falling below them. If there are no devices below, only the hacker's device would be impacted.

San Diego Office

- Topology: **Mesh**

- If the hacker disrupts the network traffic from their location, only the hacker's device will be impacted. The office's network will still work, as each device has another connection to the others.

- If the hacker disrupted the network traffic from any other device, only the hacker's device would be impacted. The office's network would still work as each device has another connection to the others.


Tokyo Office

- Topology: **Hybrid**

- If the hacker disrupts the network traffic from their assumed location, only the hacker's device will be impacted. The office's complete network will still function.

- If the hacker disrupted the network traffic from the ring section of the topology, all the devices in the ring topology would be affected.

- If the hacker disrupted the network traffic from the star section of the topology (not including the center device of the star), only the device disrupted will be affected. 

- If the hacker disrupted the network traffic from the bus section of the topology, all the devices could lose some form of connectivity depending where the traffic originates from.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.