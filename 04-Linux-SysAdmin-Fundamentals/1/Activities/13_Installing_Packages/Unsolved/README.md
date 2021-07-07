## Activity File: Installing Packages

Now that we have stopped a malicious service from running and completed a basic audit, we're now going to cover some of the miscellaneous utilities that we can install onto our VMs. Specifically we'll install the following services:

- `emacs` is a traditional file editor. 
- `cowsay` is a utility that takes in input and displays a cow repeating it. 
- `fortune` is a utility that will give you a random proverb that may be interesting to the user. 


### Instructions

1. To install the packages `emacs`, `cowsay`, and `fortune`, you will need to use the command that you have learned from the Installing Packages lecture.

   Each time you install a package, `apt` will ask for permission to use the disk space needed to install the package.

    - Use the man pages to find a flag that lets you automatically answer `yes` to any prompts that come up when installing a package.

    - Install the remaining packages by using this command. 

2. Next we will want to use our new packages. Use the following commands to run your new utilities:

   - `emacs` will open your new text editor.  
   - `cowsay hello` will start a new line with a cow saying "hello."
   - `fortune` will output the proverb of the day. 

#### Bonus

3. Find the command that will let you install multiple packages with a single command.

4. Combine the cowsay and fortune utility by running the following command:
   - `fortune | cowsay`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
