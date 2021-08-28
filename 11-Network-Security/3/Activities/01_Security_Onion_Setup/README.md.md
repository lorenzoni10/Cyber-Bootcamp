
## Activity File: Security Onion Setup

To prepare for the labs, we will all log into Azure and launch an instance of Security Onion. This will generate alert data that will allow us to complete the labs.

Log into the Security Onion machine with the following credentials:

- Username: `sysadmin`
- Password: `cybersecurity`

### Instructions

1. First, we will all verify that our network security monitoring (NSM) tools are 100% operational before starting the labs. Launch the terminal.

   - Run the following command to check the status of currently installed NSM tools.

      - `sudo so-status`

   - Output should look similar to below:

      ![NSM Status](Images/SO%20Status.png)


   - Ensure all statuses are `OK`.
   
   - If not, repeat the `so-status` command a few times. Sometimes it's slow.
   
   - If any of the statuses are not `OK` after a few minutes, restart Security Onion's NSM tool with the following command:

      - `sudo so-restart`
   
   - Keep running the `so-status` command for a few minutes. All systems should reflect `OK` after a few minutes.


#### Generate Alerts

2. Next, log into Sguil to verify that your PCAPs are still populated. 

    - Your Sguil login credentials are:

        - Username: `sysadmin`

        - Password: `cybersecurity`

    - Verify that you still have their pcaps loaded from the previous class. If this is not the case, run the following command to replay all PCAP files from previously captured malware:

        - Run:`sudo so-replay`

        - It could take as long as 10 to 15 minutes for Security Onion to run all of the PCAPs.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
