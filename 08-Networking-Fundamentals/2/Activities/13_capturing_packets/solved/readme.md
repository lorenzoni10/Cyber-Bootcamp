## Solution Guide: Capturing Packets

The goal of this exercise was to introduce the user interface of Wireshark, and practice how to capture packets and make configuration changes to assist with analysis.

Completing this activity required the following steps:

  - Capturing web traffic with Wireshark.

  - Configuring five settings in the Wireshark interface.

  - Viewing the captured logs to confirm the settings took effect.

---

Capture live web traffic on your network with Wireshark:

- Within the Wireshark interface, click on the logo to initiate the Wireshark capture.
- Open a web browser and navigate to any website.
- Return to the Wireshark application and click on the red square to stop the capture.

Make the following configurations to your Wireshark application:
   - Configure time to display the date and time of day so you can easily see when a certain activity is occurring.

      - Within the Wireshark user interface, navigate on the top display bar.
      - Select `View` > `Time Display Format` > `Date and Time of Day`.

   -  Configure HTTP to display as a distinct color of your choice:

      - Navigate on the top display bar.
      - Select  `View` > `Coloring Rules` > `Highlight HTTP`.
      - Select `Background` and choose a color.
      - Select `OK` to save the settings.

   -  Configure the network translation to display the webpage being accessed:

      - On the top display bar, select `View` > `Name Resolution` > Check `Resolve Network Addresses`.

   -  Add additional columns, such as source and destination port:

      - Within the Packet Details pane (the middle pane), right-click each value and select `Apply as Column`.     
       
   -  Remove the column “New Column”:

      - Right-click on the `New Column` column > Select `Remove this Column`.

---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.