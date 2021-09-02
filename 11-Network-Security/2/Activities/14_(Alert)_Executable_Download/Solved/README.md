## Solution Guide: Alert - ET INFO Executable Download

The goal of this activity was to reinforce concepts related to Snort IDS, Security Onion, and network security monitoring.

---

1. Open the Sguil analyst console and filter the source IP `10.2.28.101`. 

2. Right-click on the alert that contains the following Snort Message: `ET INFO Executable Download from Dotted Quad Host`. Click on **Transcript** and answer the following questions:

    - What is the name of the file included in the SRC HTTP Response?

        - `go.exe`

    - Was the file compressed prior to exfiltration and if so, what compression method did the attacker use?

        - Yes, gzip.


    - Why would an attacker compress files prior to exfiltration?

        - Small files transfer more quickly than big files.

    - Scroll to the bottom of the Transcript window. Name the four DLL file imports.

        - `ADVAPI32.DLL`, `GDI32.DLL`, `KERNEL32.DLL`, `USER32.DLL`

Close the Transcript window.

3. Back in Sguil, pivot to NetworkMiner by right-clicking on the Alert ID that contains the Snort message `ET INFO Executable Download from Dotted Quad Host`.

4. Click on the **Files (1)** tab and open the folder where the `go.exe` virus is stored on the local hard drive.

5. Open the Chromium browser in Security Onion and bring up the www.virustotal.com webpage.

6. Drag the `go.exe` file into the VirusTotal website and answer the following questions:

    - How many virus signature matches are there?

        - 58

    - Go to the **Details** section of VirusTotal and scroll down to the **Imports** section. Do the four files listed match what you entered as the four DLL file imports?

         - Yes, all four files match.

    - Scroll to the top of the **Details** window and take note of the PEiD line. Research and define what **UPX** is.

        - UPX is a free, portable, extendable, high-performance executable packer for several executable formats.

7. In the VirusTotal website, click on the **Relations** tab and answer the following:

    - How many URLs were contacted?

        - 9

    - How many domains were contacted?

         - 2

    - How many IP addresses were contacted?

        - 4

    - What three countries were contacted during this attack? 

        - United States, France, and Singapore

8. In the VirusTotal website, click on the **Behaviors** tab and answer the following question:

     - How many registry keys were deleted?

        - Answer: 7

9. Back at the Sguil analyst console, click on the **IP Resolution** tab and answer the following questions:

    - What is the person, address, and phone number of the DNS registrant associated with the IP `51.15.252.131`?

        - Filter for the Dst IP of `51.15.252.131`. In the IP resolution box, check "Dst IP" and scroll until you see
        `Mickael Marchand, Address = 8 rue de la ville l'eveque 75008 PARIS, Phone = +33173502000`

     - What is the email address for reporting abuse?

        - abuse@online.net

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
