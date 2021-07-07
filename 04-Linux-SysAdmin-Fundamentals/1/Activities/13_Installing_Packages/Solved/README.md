## Solution File: Installing Packages

To install the packages `emacs`, `cowsay`, and `fortune`, we need to use the command `apt` with the following syntax:
    
`sudo apt install <package>`

- `emacs` is a traditional file editor. 
- `cowsay` is a utility that takes in input, and displays a cow repeating it. 
- `fortune` is a utility that will give you a random proverb that may be interesting to the user. 


### Instructions

1. Each time you install a package, `apt` will ask for permission to acquire the disk space needed to install the package.
  
- Use the man pages to find the flag that lets you automatically answer `yes` to any prompts that come up when installing a package:
    -  Run `man apt`

     - The flag is `sudo apt -y install <package name>`.

To install the remaining packages, run the following commands:

- `sudo apt -y install cowsay`

- `sudo apt -y install fortune` 

2. Next we will want to use our new packages. Use the following commands to run your new utilities:

   - `emacs` will open your new text editor.  
   - `cowsay hello` will start a new line with a cow saying "hello."
   - `fortune` will give you a new and interesting proverb for the day. 
  
**Bonus**

- Is there a way to install multiple packages with a single command?
    - Yes. Include each package name in the command, separated by a space: 
    
      `sudo apt -y install emacs cowsay fortune`

- Combine the cowsay and fortune utility by running the following command:
  - `fortune | cowsay`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
