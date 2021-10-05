## Activity File: Alert - ET INFO Executable Download

In this activity, you continue in your roles as an SOC analyst for the California DMV.

- Your organization has just experienced another attack. Snort identified this attack as an emerging threat: an executable download designed to upload data to the attacker.

- You will need to discover the intent of the attack and prepare a report that includes the tactics, techniques, and procedures used by the adversary.


### Instructions

- Use the following indicators of attack to complete the activity: 

    - Source IP: Attacker = `10.2.28.101`
    - Destination IP: Victim = `51.15.252.131`
    - Snort message: `ET INFO Executable Download from Dotted Quad Host`
    - Destination port: `80`

1. Open the Sguil analyst console and filter the source IP `10.2.28.101`. 

2. Right-click on an alert that contains the following Snort Message: `ET INFO Executable Download from Dotted Quad Host`. Click on **Transcript** and answer the following questions:

    - What is the name of the file included in the SRC HTTP Response?

    - Was the file compressed before it was exfiltrated and if so, what compression method did the attacker use?

    - Why would an attacker compress files before exfiltrating them?

    - Scroll to the bottom of the Transcript window. Name the four DLL files imports.

Close the Transcript window.

3. Back in Sguil, switch to NetworkMiner by right-clicking on the Alert ID that contains the Snort message `ET INFO Executable Download from Dotted Quad Host`.

4. Click on the **Files (1)** tab and open the folder where the `go.exe` virus is stored on the local hard drive.

5. Open the Chromium browser in Security Onion and bring up the www.virustotal.com webpage.

6. Drag the `go.exe` file into the VirusTotal website and answer the following questions:

    - How many virus signature matches are there?

    - Go to the **Details** section of VirusTotal and scroll to the **Imports** section. Do the four files listed match what you entered as the four DLL file imports?

    - Scroll to the top of the **Details** window, and take note of the PEiD line. Research and define what **UPX** is.


7. In the VirusTotal website, click on the **Relations** tab and answer the following:

    - How many URLs were contacted?


    - How many domains were contacted?


    - How many IP addresses were contacted?


    - What three countries were contacted during this attack? 
        - *Hint: Use Google*.


8. In the VirusTotal website, click on the **Behaviors** tab and answer the following:

    - How many registry keys were deleted?


9. Back at the Sguil analyst console, click on the **IP Resolution** tab and answer the following questions:

    - What is the person, address, and phone number of the DNS registrant associated with the IP `51.15.252.131`?


    - What is the email address for reporting abuse?
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


