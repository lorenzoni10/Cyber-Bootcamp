## Activity File: Cryptography Refresher

You will continue your role as a security analyst working for the Hill Valley Police Department. 

- In the last class, you determined that the Alphabet Bandit is likely an insider, as a forged message told you to investigate *outside* of the Hill Valley Police Department.

- Since the Alphabet Bandit has yet to be identified, and in order to protect your fellow police officers, you want to remind everyone to be sure to use digital signatures to create and verify messages.

- Your task is to create a message reminding your fellow officers to use digital signatures. 

- Be sure to follow your own advice by clearsigning the message, and then share it with your fellow officers.
 


### Instructions

1. Verify that you can see your gpg key by running: `gpg --list-keys`. 
   - Note: If you can't see your gpg key, reinstall it using `gpg --gen-key`. 

```
sysadmin@UbuntuDesktop:~$ gpg --list-keys
/home/sysadmin/.gnupg/pubring.kbx
---------------------------------
pub   rsa3072 2020-05-27 [SC] [expires: 2022-05-27]
      FE5AAFF8365F5CD2DB305089DDD05BF1DC3F40C8
uid           [ultimate] sysadmin
sub   rsa3072 2020-05-27 [E] [expires: 2022-05-27]
```

2. Write a simple message reminding your fellow Hill Valley officers to sign and verify all messages until further notice.

3. Using GPG, clearsign the message with a digital signature, and name your output file with your name, such as: `Important_Communication_by_Myname` 


4. Working with the same partner as in the assymetric key activity from last class, send the clearsigned message to the partner.

    - Note: If this partner isn't available, join another group to exchange exported public keys and clearsigned messages with.

5. Once you receive the clearsigned message from your partner, use GPG to verify the message is authentic. 

---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
