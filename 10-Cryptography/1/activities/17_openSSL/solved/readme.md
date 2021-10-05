## Solution Guide: OpenSSL

The goal of this exercise was to practice using the symmetric encryption tool OpenSSL to provide confidentiality when transmitting secure messages.

Completing this activity required the following steps:

- Writing an OpenSSL command to decrypt an encrypted message.

- Decrypting the message using OpenSSL and reading the plaintext instructions.

- Writing a new plaintext message.

- Create a IV and a key with OpenSSL.

- Encrypting a new message using OpenSSL.

---

- First, download the `communication.txt.enc` file into your virtual machine.
  - Run: `wget tinyurl.com/s99665v`

- Rename the `s99665v` file you have downloaded, to `communication.txt.enc`. 
  - Run: `mv s99665v communication.txt.enc` 

- Next, download and read the Key and IV file
- Run: `wget tinyurl.com/yx8boxpp`
- Run: `cat yx8boxpp`

- From the command line write the following command to decrypt the message:
    `openssl enc -pbkdf2 -nosalt -aes-256-cbc -d -in communication.txt.enc -base64 -K 346B3EFB4B899E8205C4B35E91F5A4605A54F89730AE65CA2C43AB464E76CA99 -iv 759D1B9BF335985F55E3E9940E751B67`

  - The decrypted message will display the following:

      ```
      From: Captain Strickland

      Great Job cracking all the Alphabet's coded messages so far, but we need to act faster.

      I need you and your partner to meet me at Lou's Cafe tomorrow at noon.
      I have some additional information to share about the Alphabet Bandit.

      I need you to do the following things:

      1) Write a message called "meetingplace.txt" for your partner, letting them know about the secret meeting tomorrow 
      2) In the message don't use your real names!
      3) Create a new Key and IV with Open SSL
      4) Use Open SSL with that Key and IV to encrypt the message
      5) Don't send the message until we give you the green light
      ```

- To complete the first step, create a message called `meetingplace.txt` that includes a message similar to the following:

    `Hi [partner's code name], this is [your code name]. Tomorrow we will be meeting Captain Strickland at noon at Lou's Cafe to discuss some additional information about the Alphabet Bandit`
    
- To create a the new key and IV, run the following:

  `openssl enc -pbkdf2 -nosalt -aes-256-cbc -k [password here] -P > key_and_IV`
       
- View the key and IV and and use the data to encrypt the message with the following command:

  `openssl enc -pbkdf2 -nosalt -aes-256-cbc -in meetingplace.txt -out meetingplace.txt.enc -base64 -K <key> -iv <iv>`

- Validate the encrypted message has been created by running:

    `cat meetingplace.txt.enc`
      
---      
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
