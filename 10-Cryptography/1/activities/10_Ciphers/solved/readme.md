## Solution Guide: Ciphers
In this activity, you used a key to decrypt ciphertext to make it plaintext.

Completing this activity required the following steps:

  - Viewing the cipher text and the key.

  - Breaking up the text into blocks.

  - Using the key to reverse the ciphertext into plaintext. 
---

First, we examine the key : `{123456} = {341256}`.

  - The text is divided into blocks of six characters.

    **Note**: Spaces are characters.

  - In these blocks of six, the first character is transposed with the third character, the fourth character transposed with the second, and so on.   
  
    The transpositions are below, with the first number being the original placement, and the second number the placement after the key is applied. 
    - 1 > 3
    - 2 > 4
    - 3 > 1
    - 4 > 2 
    - 5 > 5 
    - 6 > 6 

- The ciphertext is converted in blocks of six.

  - For example, **u Yoca** will be converted by doing the following:

    - Take the third character in the ciphertext (**Y**) and place it in the first spot.
    - In the second spot, place the fourth character: **o**
    - The third spot, the first character: **u**
    - The fourth spot, the second character: **[space]**
    - The fifth spot, the fifth character: **c**
    - The sixth spot, the sixth character: **a**
  - When put together, we get:  **You ca**  
  - **nen	ve** will be converted to **n neve** with this same conversion.

 When applied to all the blocks of six characters, the decrypted message reads:
  - **You can never catch the Alphabet Bandit, My next Target is Calvins House**.

----
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.