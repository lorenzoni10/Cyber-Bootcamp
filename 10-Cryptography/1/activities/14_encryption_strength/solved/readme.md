## Solution Guide: Encryption Strength
The goal of this activity was to illustrate that the basis for cryptography is mathematics, and that "trusting the math" is a critical concept for security professionals when it comes to determining adequate security levels.

Completing this activity required the following steps:

- Determining the current level and speed of decryption.

- Calculating how many additional seconds each additional bit will add to decryption.

- Converting the seconds into days, months, or years.

- Selecting the most cost-efficient security based on requirements.
---


The first step is to understand the following concepts:
  
  - It takes one second to crack 64-bit encryption with current technology.
  
  - Each additional bit doubles the number of seconds to crack the encryption.
  
    - For example:
  
      - 65-bit encryption = 1 additional bit = 2 to the first power =  2 seconds to decrypt
  
      - 66-bit encryption = 2 additional bits = 2 to the second power = 4 seconds to decrypt
      
      - 69-bit encryption = 5 additional bits = 2 to the fifth power = 32 seconds to decrypt
      
We will use these same math principles to evaluate the vendor's security:      
      
 - Vendor Twin Pines Email offers 84-bit encryption for $10,000 a month.
     
     - 84-bit encryption = 20 additional bits = 2 to the 20th power =  1,048,576 seconds = 12 days to decrypt
     
 - Vendor Marvin's Secure Email offers 96-bit encryption for $40,000 a month.
     
     - 96-bit encryption = 32 additional bits = 2 to the 32nd power =  4,294,967,296 seconds = 136 years to decrypt   
     
 - Vendor Milton's Steel Emails offers 103-bit encryption for $100,000 a month.
     
     - 103-bit encryption = 39 additional bits = 2 to the 39th power =  549,755,813,888 seconds = 174 centuries to decrypt.       

We would recommend selecting Marvin's Secure Email as the most cost-efficient vendor, as they're able to protect emails from being decrypted for over one hundred years.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.