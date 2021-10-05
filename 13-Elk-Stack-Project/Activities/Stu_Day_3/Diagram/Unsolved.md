## Activity File: Diagramming the Network

Now that you've deployed your ELK instance, your virtual network is stable. You won't be adding anything to it for awhile.

Since the network is essentially complete, it's time to document what you've built. This is an important last step for any deployment.

### Instructions

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


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
