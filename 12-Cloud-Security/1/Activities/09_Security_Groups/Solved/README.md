## Solution Guide: Security Groups

In this activity, you set up a firewall in front of your VNet to block all traffic.

---

To create a network security group:

- On your Azure portal home screen, search "net" and choose **Network security groups**. 

- Create a new security group.

- Add this security group to your resource group.

- Give the group a recognizable name that is easy to remember.

- Make sure the security group is in the same region that you chose during the previous activity.

To create an inbound rule to block all traffic:

- Once the security group is created, click on the group to configure it.

- Choose **Inbound security rules** on the left.

- Click on the **+ Add** button to add a rule.

Configure the inbound rule as follows:

- Source: Choose **Any** source to block all traffic.

- Source port ranges: Source ports are always random, even with common services like HTTP. Therefore, keep the wildcard (*) to match all source ports.

- Destination: Select **Any** to block any and all traffic associated with this security group.

- Service: Select **Custom**

- Destination port ranges: Usually, you would specify a specific port or a range of ports for the destination. In this case, you can use the wildcard (*) to block all destination ports. You can also block all ports using a range like `0-65535`.

- Protocol: Block **Any** protocol that is used.

- Action: Use the **Block** action to stop all of the traffic that matches this rule.

- Priority: This rule will always be the last rule, so it should have the highest possible number for the priority. Other rules will always come before this rule. The highest number Azure allows is 4,096.

- Name: Give your rule a name like "Default-Deny."

- Description: Write a quick description similar to "Deny all inbound traffic."

- Save the rule.

You should now have a VNet protected by a network security group that blocks all traffic.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
