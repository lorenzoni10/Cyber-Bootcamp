## Solution Guide: Network Devices

To complete this activity, you had to design a network layout for the new Shanghai office using  **Gliffy**. 

---
The solution below is a general guideline. There are many ways to design the Shanghai network with the required devices. Use the following as guide for reviewing your own design.

It's important that your design includes the following characteristics: 

  1. The internet is protected by a firewall.
  
  2. The load balancers are placed after the firewall.
  3. The router comes after the load balancers.
  4. The switches come after the router.
  5. The computers come after the switches.
  6. The server can be placed in many places, as long as it is behind the load balancers.
  7. There is a firewall between the wireless access point and the network.
  8. The firewall for the wireless access point connects somewhere in the network (behind the load balancers).

  ![shanghai office design](Images/shanghaioffice_bonus.png)


### Bonus
 
Add the following:

  9. An additional firewall separating the load balancers and server from the LAN.

  10. Line indicating the separation of the DMZ, LAN, and WAN.

  ![shanghai office bonus](Images/shanghai_bonus.png)

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
