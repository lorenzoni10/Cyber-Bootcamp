## Activity File: Heartbleed and SearchSploit

In this activity, you are a pentester for a client that uses OpenSSL. 

- You are concerned about the server's susceptibility to the Heartbleed vulnerability. 

- You are tasked with  using SearchSploit to identify if your client's machine is vulnerable to Heartbleed. 


### Instructions

Log into your Kali Linux with the following credentials: 
  - Username: `root`  
  - password: `toor`

The Heartbleed machine will act as the victims computer:
  - Username: `vagrant`  
  - password: `vagrant`

  You will be using this machine to exploit the Heartbleed VM.

1. Use `searchsploit` to identify Heartbleed exploits.

2. Inspect the Python exploits you identify:
    
    - Read the source code of each exploit with the `-x` option. 

      - **Hint:** `searchsploit -x <exploit>`

    - What's the difference between the two exploits you found?

3. Move to the directory containing the exploit that adds SSL/TLS support and attempt to run it against the Heartbleed VM. 

---
&copy; 2020 Trilogy Education Services, a 2U Inc Brand. All Rights Reserved.
