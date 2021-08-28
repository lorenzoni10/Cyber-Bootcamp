## Activity File: Security Onion Setup

To prepare for today's labs, log into Azure and launch an instance of Security Onion. This will generate PCAPs that will use in the activities.

Log in with the following credentials:

- Username: `sysadmin`
- Password: `cybersecurity`

### Instructions 

1. First, we will all verify that our network security monitoring (NSM) tools are working before starting the labs. Click on **Applications** > **Other** > and scroll down to **Terminal**. Click to launch the terminal type the following command:
   
    - `sudo so-status`
      
       - `so-status`: Checks the status of currently installed NSM tools.
   
    - Output should look similar to below:
   
     ![NSM Status](SO%20Status.png)
   
      - Ensure all statuses are listed as `OK`.
      - If not, let the `so-status` command run for a few minutes. It can be slow.
   
    - If any of the statuses are not listed as `OK` after a few minutes, restart the NSM tools with the following command:

       - `sudo so-restart`
   
    - Run the `so-status` command again for a few minutes. All systems should be listed as `OK` after a few minutes.


2. Next, we need to generate alerts.  

   - Run `sudo so-replay`

      - `so-replay` is the command used by Security Onion to "replay" all PCAP files from previously captured malware.

   - It can take as long as 10 to 15 minutes for Security Onion to run all of the PCAPs. This will be running as we move into the first lecture. 

   - :warning: `so-replay` should be completed before starting the activities.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
