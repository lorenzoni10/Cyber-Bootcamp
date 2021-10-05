## Activity File: OpenSSL 

In this activity, you will continue to play the role of a security analyst working for the Hill Valley Police department.

- Captain Strickland thanks you for selecting the best email vendor, but unfortunately it takes a few weeks for this vendor to install their systems.

- Captain Strickland needs to still communicate with you securely, so they sent you an urgent message, encrypted with OpenSSL.

- Your task is to decrypt the message and follow the instructions.

- In this activity you will also use the command called `wget` from the Linux weeks to grab the files that you need. 

### Instructions

1. Download the encrypted message onto your virtual machine using wget:
- Run: `wget tinyurl.com/s99665v` to download the file. 

2. Rename the `s99665v` file you have downloaded, to `communication.txt.enc`. 
  - Run: `mv s99665v communication.txt.enc` to rename the file. 

3. Download the Key and IV 
- Run: `wget tinyurl.com/yx8boxpp` to download the file. 
- Run: `cat yx8boxpp` to read the file. 
  - **Note:** You'll need to copy parts of this file for the command that you will be using. 

4. Use OpenSSL with the key and IV provided to decrypt the message.
  
5. Use the following options when decrypting:
    - `-pbkdf2`
    - `-nosalt`
    - `-aes-256-cbc`
    - `-base64`

6. Follow the instructions provided in the decrypted message.
   
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
