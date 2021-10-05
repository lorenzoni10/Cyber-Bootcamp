## Solution File: Hashcat

 The goal of this activity was to illustrate how Hashcat can be used to determine the plaintext value of a hash. You ran the Hashcat script to determine the password needed to open an encrypted file.

---

- First, we place the hash into a file.

  - We will place it into a file called `hash.txt` by running the following:

    - `echo f31663d6c912b0b1ced885a6c6bbab7c > hash.txt`

  - Run the command and preview the file to confirm the hash has been placed inside:  
  
    - `more hash.txt`

- Next, write the Hashcat command:
  
  - `hashcat -m 0 -a 0 -o solved.txt hash.txt /usr/share/wordlists/rockyou.txt --force`

- The syntax is:
  - `hashcat`: The command to execute Hashcat.
  - `-m 0`: Uses the MD5 hash (which was created by Ronald Rivest in 1992).
  - `a 0`: Applies a dictionary attack.
  - `-o solved.txt`: Creates an output file called `solved.txt`. 
  - `hash.txt`: The input file of the hash.
  - `/usr/share/wordlists/rockyou.txt`: The location of the wordlist we will check against.
  - `--force`: Overrides any small errors that may occur.

- Run the command. This will place the results in the file called `solved.txt`.

- Open the `solved.txt` file. It tells us that the hash represents the value `ilovelorraine`:

   - `f31663d6c912b0b1ced885a6c6bbab7c:ilovelorraine`

- Open the file `secret.zip` using the command `unzip secret.zip`. 

- When it prompts for the password, enter `ilovelorraine`.

- This reveals the Alphabet Bandit's confession letter:

```
CONGRATULATIONS TO THE CYBER SLEUTH THAT FINDS THIS MESSAGE!!


My Confession

  I, Detective Tannen, am confessing that I am the Alphabet Bandit! 

  I am the one solely responsible for all of the Hill Valley Break-ins.

  Since I wasn't promoted to Captain, I have been determined to cause havoc to the Hill Valley community and tie up the Hill Valley Resources.

  Unfortunately, since you have found this message, I will assume that I will be prosecuted and the break-ins will cease.

Sincerely,
Detective Tannen
```
---

 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
