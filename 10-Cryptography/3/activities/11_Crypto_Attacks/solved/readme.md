## Solution File: Cryptographic Attacks 

The goal of this activity was to use a chosen-plaintext attack method to crack a password. You used an algorithm that converts plaintext into ciphertext to determine the plaintext of an encrypted text.

---

- First, download the two scripts (`encrypter.py` and `password.py`) to your virtual machine.
  
- Next, test the `encrypter.py` with several plaintext words to see the results.
  - For example, if you run `python3 encrypter.py`, you will be asked:
      ```
     What is your password?
      ```
  - We will first test:  **hello**. The following is returned:

      ```
      Your Password is: hello
      Your Encrypted Password is: axeeh
      ```

   - We can determine that the letters are being substituted, as both **l**s are substited with an **e**. 

   - We will test it again with one letter, **a**,  to see if we can determine the algorithm. The following is returned:

      ```
       Your Password is: a
       Your Encrypted Password is: t
      ```
   - Since **a** is the first letter in the alphabet, and **t** is the twentieth letter in the alphabet, we can conclude that this algorithm is a Caesar cipher shifting the letter 19 characters. 
   
   - Let's apply this algorithm in reverse for each letter.
     - A good way to do this is to write or type out the whole alphabet and count 19 characters to the left for each letter of the encrypted password.

     - If you pass the letter **a** while counting, start back at the letter **z**.

   - Once we apply this to every letter, the plaintext of Detective Tannen's encrypted password (**cbzhptmm**) is decrypted as **jigowatt**.

 - Next we will test out this password by running `python3 password.py`. This will return the following:

      ```
      Hi Mr Tannen,  What is your password (lowercase only) ?
      ``` 
      
  - Enter in the password `jigowatt`, and the following will be returned:
      ```
      Hello Detective Tannen, the last file you accessed is: topsecret.txt.
      ```



---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
