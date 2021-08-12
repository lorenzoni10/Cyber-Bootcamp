## Solution Guide: OSI

The goal of this exercise was to introduce the OSI layers and practice identifying what types of activities, protocols, and devices exist at each layer.   

Completing this activity required following steps:

   - Reviewing each recent suspicious network-related event that occurred at Acme Corp.

   - Determining at which OSI layer each of the incidents occurred.

--- 

1. A networking cable was cut in the Data Center and now no traffic can go out.

   **Solution:**  Physical cables that are cut or disconnected occur on Layer 1: the Physical layer.

2. A code injection was submitted from an administrative website, and it's possible that an attacker can now see unauthorized directories from your Linux server.

   **Solution:**  Attacks that occur directly on the web application would occur on Layer 7: the Application layer.

3. The MAC address of one of your network interface cards has been spoofed and is preventing some traffic from reaching its destination.

   **Solution:**   Issues or attacks on the MAC Address would occur on the Layer 2: the Data Link layer.

4. Your encrypted web traffic is now using a weak encryption cipher and the web traffic is now vulnerable to decryption.

   **Solution:**  Encryption occurs on the Layer 6: Presentation layer. 

5. The destination IP address has been modified and traffic is being routed to an unauthorized location.

   **Solution:** IP Addresses and IP address routing occurs on Layer 3: the Network layer.

6. A flood of TCP requests is causing performance issues.

   **Solution:** TCP and source and destination protocols occur on Layer 4: the Transport layer.

7. A SQL injection attack has been detected by the SOC. This SQL injection may have deleted several database tables.

   **Solution:** Attacks occurring on the web application occur on Layer 7: the Application layer.

8. A switch suddenly stopped working and local machines aren't receiving any traffic.

   **Solution:** Switches use MAC Addresses to route traffic, so this would occur on Layer 2: the Data Link layer. 

9. An ethernet cable was disconnected and the machine connected isn't able to receive any external traffic.

   **Solution:** Physical cables that are cut or disconnected occur on Layer 1: the Physical layer.

10. Traffic within the network is now being directed from the switch to a suspicious device.

    **Solution:** Switches use MAC Addresses to route traffic, so this would occur on Layer 2: the Data Link layer. 

--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.