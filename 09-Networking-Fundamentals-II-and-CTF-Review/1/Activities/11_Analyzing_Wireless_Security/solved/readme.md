## Solution Guide: Analyzing Wireless Security

In this exercise, you used Wireshark to analyze a packet capture from the newly acquired Kansas City office, finding all wireless routers in this office as well as the SSID, BSSID, and type of encryption from these devices.

Completing this activity required the following steps:

- Using Wireshark to determine how many wireless routers are in the Kansas City office.

- For each wireless router, adding a column to determine the following:

  - SSID
  - BSSID
  - Type of wireless security
   
---

**SSID and BSSID**

- To view the SSID in a column, right-click the following values and select `Add a column`.
  - `IEEE 802.11 wireless LAN`  > `Tagged parameters` >`Tag: SSID parameter set` > `SSID`
  
  
- To view the BSSID in a column, right-click the following values and select `Add a column`.
  - `IEEE 802.11 Beacon frame` > `BSSID`

  You should see: 
    
    ```bash
      BSSID                     SSID 
      00:01:e3:41:bd:6e         martinet3       
      00:0c:41:82:b2:55         Coherer 
      00:14:6c:7e:40:80         teddy    
      00:12:bf:12:32:29         Appart
  ```                    
                     

**Type of Wireless Security**
 

- To view the wireless security in a column, right-click the following values and select `Add a column`.
  - `IEEE 802.11 wireless LAN` > `Tagged parameters` > `Tag: Vendor Specific: WPA Information Element` >  `WPA Version`
  
- To check the wireless security for non-WPA devices, select `Wireless`  from the toolbar. The `Protection` column will display if WEP is detected.  

  You should see: 

  ```bash
  SSID                 Wireless Security    
  martinet3              WPA1   
  Coherer                WPA1
  teddy                  WPA1
  Appart                 WEP
  ```
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.