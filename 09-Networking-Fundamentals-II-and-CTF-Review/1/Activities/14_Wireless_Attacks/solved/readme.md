## Solution Guide: Wireless Attacks

In the exercise, you analyzed a packet capture from a wireless router, found the key for the wireless router, and used the key to decrypt the wireless traffic.

Completing this activity required the following steps:

- Open the kansascityWEP.pcapng file in wireshark

- Using Aircrack-ng against the packet capture to determine the secret key.

- Using the key to decrypt the traffic.

- Analyzing the decrypted traffic and determining any associated security risks.

---

- Save the packet capture file on your Kali Linux server in an accessible location.

- Use Aircrack-ng against the packet capture to determine the secret key.

  From the command line, go to the location where the packet capture was saved.

  - Run `aircrack-ng kansascityWEP.pcap`

  - The results should show that the secret key is:

    `KEY FOUND! [ 1F:1F:1F:1F:1F ] `


- Use the key to decrypt the traffic.

  - Open the file `kansascityWEP.pcap` in Wireshark.

  - Make sure the Wireless Toolbar is added by going to `View`, and checking `Wireless Toolbar`.

  - Scroll up and down through the traffic. There should only be a wireless protocol of `802.11` in the Protocol column.

  - Click on `802.11 preferences` in the toolbar.

  - Select `Enable Decryption`.

  - Click on the `Edit` option next to decryption keys.

  - Click on the `+` icon to add the key.
  - Select `WEP` and paste in the key of `1F:1F:1F:1F:1F`.
  - Select `OK`.



- Analyze the decrypted traffic and determine the associated security risks.
  - Return to the Wireshark packet capture.

  - Note that there are now new decrypted packets identified by a light pink color.

  - The protocols for the decrypted traffic are ARP and IGMP.

  - The security risk is that a hacker can use the decrypted information from ARP to determine internal private server IP addresses.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
