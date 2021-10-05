## Solution Guide: Cryptography Refresher
The goal of this exercise was to review how to use OpenSSL and illustrate the challenge that securely exchanged keys pose to security professionals.


---

- Write a message (you can use Nano or Vi) to create a message  titled `meetingplace_update.txt` containing the following information:

    ```
    Dear [partner's code name]

    Captain Strickland would like us to now meet at Lou's Cafe at 6 p.m. to discuss some additional information about the Alphabet Bandit. See you there!

    From, 
    [your code name]
    ```               
 - Use OpenSSL to encrypt the message by running the following:
 
    `openssl enc -pbkdf2 -nosalt -aes-256-cbc -in meetingplace_update.txt -out meetingplace_update.txt.enc -base64 -K <your_key> -iv <your_iv>`
               
 - Send the following to your partner:
      - `meetingplace_update.txt.enc`
      - Key
      - IV
     
- Upon receiving your partner's message, key, and IV, decrypt the message with the following command, updated with your partner's key and IV in the correct locations:

    `openssl enc -pbkdf2 -nosalt -aes-256-cbc -d -in meetingplace_update.txt.enc -base64 -K [partner key] -iv [partner IV]`
           
- It's likely that most of you used Slack or email to transmit the key and IV. While Slack and email may seem secure:
        
    - Emails are typically not encrypted.
    - Slack administrators can have access to view private messages between parties.
---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
