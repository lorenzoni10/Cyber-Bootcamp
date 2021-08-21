## Activity File: Cryptographic Attacks

You will continue your role as a security analyst working for the Hill Valley Police Department.

- Captain Strickland shared some news: they have been secretly capturing and monitoring all the online activity of the Hill Valley detectives.

- They believe that Detective Tannen is the Alphabet Bandit, as Tannen has been recently saving suspicious encrypted files on their computer.

- The captain believes these encrypted files contain evidence that can be used to prosecute Detective Tannen.

- While capturing Detective Tannen's online activity, Captain Strickland was able to capture the following:
    - Detective Tannen's password encryption script, which generates encrypted passwords from plaintext.

    - Detective Tannen's encrypted password, which is **cbzhptmm**.

- Your task is to see if you can figure out the algorithm of the encryption script to figure out Detective Tannen's plaintext password.

- Then, you will try to use Detective Tannen's password to log into their account and gather evidence that they are the Alphabet Bandit.


### Instructions

1. Enter any plaintext into the Password Encrypter and determine the algorithm being used for encryption.

    - To run the password encrypter, run: `python3 encrypter.py`.
  
         *Hint: Try multiple plaintext passwords to help determine the algorithm.*

3. Once the algorithm has been determined for encryption, apply this method in reverse to determine Tannen's plaintext password from his encrypted password, **cbzhptmm**.

4. Apply this password on Tannen's login website to confirm that the password is correct. Look for any hard evidence that suggests Detective Tannen is the Alphabet Bandit. 

    - To test Tannen's Login password, run: `python3 password.py`.

---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
