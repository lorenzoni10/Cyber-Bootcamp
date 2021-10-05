## Solution Guide: Steganography

The goal of this activity was to demonstrate how steganography is used as an applied cryptographic concept to hide a message within non-secret data, such as an image. You applied the command-line tool `steghide` to find the secret message.

---

- Save the image to your virtual machine.

- Preview the image by double-clicking the image from the desktop of your VM.
  
  - The image should display a DeLorean car:
  
       ![delorean](images/mydreamcar.jpg)
       
- Next, from the command line, go to your desktop directory to run the following `steghide` command:

  - `steghide extract -sf mydreamcar.jpg`

- When it asks for the password, enter the brand of the car:
   
  - `delorean`
         
- This extracts the hidden file, called  `list_of_targets.txt`.

- Preview the contents. This clearly reveals the previous and future targets of the Alphabet Bandit:

  ```
  List of Homes to Break Into

  Doctor Brown House - Done
  Mayor Wilson's House - Done
  Mrs Peaboday's House - Done
  Captain Strickland's house - Next
  ```
---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
