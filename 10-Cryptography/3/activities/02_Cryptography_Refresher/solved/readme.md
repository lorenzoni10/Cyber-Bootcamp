## Solution Guide: Cryptography Refresher

The goal of this activity was to practice using digital signatures with GPG, and to demonstrate that digital signatures can be used to send messages that are guaranteed to be authentic.

---

This solution is an example, as you will each have a different key and message. The following example demonstrates how to sign and verify a message with GPG.

- First, write a message to a file using echo.

    - Nano or Vi can be used to create a message. The echo command is:
    
      - `echo "This is an Urgent reminder by the security team of Hill Valley PD.  Please be sure to use GPG to sign and verify all messages" > Important_Communication_by_me.txt`
        
   - Be sure to replace the word "me" with your name.
     
- Sign the message with your private key and create an output file called `Important_Communication_by_me.sig`:
 
   -  `gpg --output Important_Communication_by_me.sig   --clearsign Important_Communication_by_me.txt`
       
- Run the script and display the clearsigned signature by running the following next command:

    - `cat Important_Communication_by_me.sig`
     
  - This should display the following:

    ```
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    This is an Urgent reminder by the security team of Hill Valley PD. 
    Please be sure to use GPG to sign and verify all messages
    -----BEGIN PGP SIGNATURE-----

    iQGzBAEBCgAdFiEEYSlws2SzZx5pJqjYHX0Iu8WCN4gFAl4OBv8ACgkQHX0Iu8WC
    N4gf/gv+PPq/qZhETpklzIjRpn620H2LpUIPqIEwqyoZ8A7WuLMTyJNjUpp6Q43T
    ZnL8fcBj5c51AswFElI4tGbWASc/YUISZCv/hMZ2q126rbTZnfvVWGlIHEuNw1La
    Ole3C7iRB845nFuY3YZGlKdr2a0X+M/SPEgvOnQP0MIYIfmCILz20ZxJjyn9H47d
    lgAZiijoMMn1OvX60BcLxj5aov6K2YgMDw63z9Z/CB/+Ue2t+M1rm/A9zAQxRiNS
    V3pdHHaBiDx3s3fieWmPR0/HJK8zUOpkzPs/SLZUkz0WZqvLv6RHE9Viab4YwjIP
    ZCaMjSrkCVuq9KwbpWE6ZFdVT3Cq/dNgRRxTuCImoRA0XzLEwLpBQIbFBozlGM/p
    ZDdzHOYkK5ZlnAF/rtmQOCVE5GFyipTXEsD2Sg4Tj52AdTl4JLKjRff5UlWsBW8D
    qJgSybjnYOGaABMIVCTAoUMC4dxGoEbZxPZZFfZKoxNViTykFIuw3xvzG0vTYz5h
    HEqplTYb
    =skQM
    -----END PGP SIGNATURE-----
    ```

  
  - This shows the plaintext message and the separate digital signature in the same file.
 
- We will pretend that the message above is the one we received from our partner.
   
  - Since you should already have your partner's public key imported from the previous activity, we don't have to repeat that step.
 
-  Verify the message by running the following command:
 
    - `gpg --verify Important_Communication_by_me.sig`
       
  -  The verification response should look similar to the following:

  ``` 
    gpg: Signature made Mon 09 Dec 2019 02:30:52 PM EST
    gpg:                using RSA key 39B2BD6C93E1E63E8C004183FE91AF7A7B4EC267
    gpg: Good signature from "me <metest.com>" [ultimate]
  ```

---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
