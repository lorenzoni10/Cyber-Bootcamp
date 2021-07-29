## Instructions for Launching Your Windows Lab

Follow these instructions to log into your lab and launch the nested virtual machines. 

### Step 1: Log into Azure Labs

1. Use RDP to log into your Windows Azure lab. 

    - Credentials for the Windows RDP Host machine:
        - Username: `azadmin`
        - Password: `p4ssw0rd*`

2. Launch the Hyper-V Manager:

    - Double-click the **Hyper-V Manager** shortcut on the desktop, or:

    - Click the bottom-left Windows icon (the Start menu button) in the Windows RDP Host machine.

    - Type "Hyper-V" in the search to show the Hyper-V Manager application.

    - Click **Hyper-V Manager** to launch the Azure virtualization lab.

Understand that Hyper-V Manager is equivalent to the VirtualBox Manager. It manages and launches virtual machines within our Azure environment.

### Step 2: Launch the Windows 10 Virtual Machine

1.  Double-click the **Windows 10 machine** to launch it. 

    - Credentials for the Windows 10 machine for today's activities:
        - Username: `sysadmin`
        - Password: `cybersecurity`

2.  Double-click the **Windows Server machine** to launch it. 

    - Credentials for the Windows 10 machine for today's activities:
        - Username: `sysadmin`
        - Password: `p4ssw0rd*`

**Note**: If you encounter save state issues, run the PowerShell command `Get-VMSnapshot | Remove-VMSavedState` within the RDP lab and relaunch the Windows 10 machine. Ask your instructional staff for help if needed.

### Step 3: Extend the Windows Virtual Machine Evaluation Licenses

This Windows 10 and Windows Server virtual machine will require an extension of the evaluation licenses so that they do not shut down abruptly.

Within the Windows 10 and Windows Server virtual machines:

1. Select the Windows icon at the bottom-left and type "CMD".

2. When the Command Prompt application appears, right-click and select **Run as administrator**.

3. Within the administrator CMD terminal window inside of the Windows 10 VM, run the following command:  
    -  `slmgr.vbs /rearm`

4. Reboot the virtual machine by clicking the Windows icon, selecting the power icon above it, and selecting **Restart**.

This will add an additional 90 days to our virtual machine evaluation license and prevent unwanted shutdowns due to expired licenses.


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.   