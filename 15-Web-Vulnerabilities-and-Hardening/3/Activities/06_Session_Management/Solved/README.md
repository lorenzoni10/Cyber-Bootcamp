## Solution Guide: Analyzing Session Management Vulnerabilities with Burp Repeater  

The purpose of this exercise is for you to see how the Repeater tool within Burp can be used to submit HTTP requests with different payloads. You used the Repeater tool to find session management vulnerabilities. You were tasked with capturing and viewing how subsequent session IDs are generated from the Replicants web server. You were then tasked with changing the security level to try and determine whether the new method for generating session IDs can be predicted.

---

1. Enable the Burp proxy.

    - First, return to Burp. Under Proxy > Intercept, confirm that **Intercept is on**.

      - If you need a recap of these steps, refer to the first activity you completed: [GitHub: Configuring Burp](https://github.com/coding-boot-camp/cybersecurity-v2/blob/15.3_V2_Update/1-Lesson-Plans/15-Web-Vulnerabilities-and-Hardening/3/Activities/03_Burp_Suite_Setup/Unsolved/README.md).

        - Drop any existing captures by continuing to click Drop until the whole capture page is empty.

    - Return to your browser and enable the Burp option on Foxy Proxy.  

2. View the HTTP request with Burp Intecept.

   - The page states, "This page will set a new cookie called `dvwaSession` each time the button is clicked."

    - Let's now capture the HTTP request that is generated when we click the button.

      - Click the Generate button. 
    
      - Note that the loading bar on the browser tab should be spinning:
    
    -  Return to Burp Suite Intercept to view this HTTP request.
    
    -  Note that you should have an HTTP POST request similar to the following:

              POST /vulnerabilities/weak_id/ HTTP/1.1
              Host: 192.168.13.25
              User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
              Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
              Accept-Language: en-US,en;q=0.5
              Accept-Encoding: gzip, deflate
              Content-Type: application/x-www-form-urlencoded
              Content-Length: 0
              Connection: close
              Referer: http://192.168.13.25/vulnerabilities/weak_id/
              Cookie: PHPSESSID=kk3k2ir7hf156ultvtetcv7br4; security=low
              Upgrade-Insecure-Requests: 1

3. Move the HTTP request to Burp Repeater.
        
    - Right-click on the Intercept page and select **Send to Repeater** (or press CTRL+R):

    - Note that now the Repeater icon color on your tool bar has changed from black to orange.

      - This indicates that the HTTP request has been sent to Repeater.
    
    - Click on the Repeater icon from your tool bar to view this HTTP request.
    
    - This should display the same HTTP POST request that you saw under Intercept.

4. Use Burp Repeater to view the HTTP response.

   - From the Repeater page, select Send to send the HTTP request.
   
      - After you select Send, the HTTP Response panel should appear on the right side of the Repeater page.

      - This data is the complete HTTP response sent back from the web server.

    - If you return to your browser, you will notice the loading bar in the browser tab is still spinning.
      
      - This means that even though the HTTP request was sent to the web server, and the web server returned the response to Burp, the response has not yet been returned to the browser.
    
    - Look at the line of the HTTP response that contains the session ID returned from the web server:
    
      - `Set-Cookie: dvwaSession=1`
    
    - Note that the first session ID is `1`.
    
    - Press the Send button again, then note how the session ID has changed:
    
      - `Set-Cookie: dvwaSession=2`
    
    - Press the Send button again several more times, and note that the session IDs increment by one digit each time.
    
    - Note that this illustrates the intended purpose of the application, to generate a different session ID every time a user selects Generate from the web application. 
    
      - Additionally, note that this is WEAK security, as an attacker could use the knowledge of how the session ID gets generated to hijack a user's session.

5. Determine the Medium-level session IDs.

    - Replicants has added more security to their web application and would like you to test whether the pattern by which the session IDs are being generated could be determined by an attacker. 

    - To test this added security, manually change the security level from Low to Medium from Burp Repeater:

      - Change `security=low` to `security=medium`:
      
        ![In the HTTP request in Burp Repeater, the code has been updated to security=medium.](burp_repeater.png)
      
    - Now press the Send button again and note how the session ID has changed in the HTTP response, to a 10-digit number:

      - Here is a sample (your number will be different): `Set-Cookie: dvwaSession=1612452171`.
    
    - Now press the Send button again and note how the session ID has changed in the HTTP response, to a different 10-digit number:
    
      - Here is a sample (your number will be different): `Set-Cookie: dvwaSession=1612452402`.
    
    - Continue to press Send to observe how the session IDs change each time. 
    
    - As a security analyst, you are tasked with determining whether the formula or method for generating each session ID can be predicted.     
    
      - **Hint**: While the Low level uses a mathematical formula (+1), to generate each session ID, the Medium level uses a different method.
    
      - **Hint**: Examine other fields in the HTTP response for clues.
    
    - Document the method used to generate these session IDs. 

    - **Solution**:

      - The DVWA session IDs generated are the actual date in seconds.

      - More specifically, the 10-digit number is UNIX time (or Epoch time).
      
      - When we use a Unix time converter we can see that 1612452171 corresponds to February 4, 2021, at 3:22pm (UTC).

      - Use the following webpage to convert the time: <https://www.unixtimestamp.com/index.php>.

      - The second row in the HTTP response, the date, is the field from which the session ID gets generated.

6. Answer the following mitigation strategy questions:

    - Describe to your management how a malicious user could take advantage of the vulnerabilities you just exploited. Be sure to include the potential impact.

      - If an attacker determines a victim's session cookie, they can access the victim's private session. The impact could include viewing a victim's confidential data inside the application or conducting unauthorized activities inside the application.

    - Describe in plain language to your manager how you would mitigate the vulnerabilities that you just exploited.

       - Mitigations can include using protective HTTP headers and generating session cookies that are difficult to predict.

7. **Bonus**: Determine the High-level session IDs.

    - Replicants has added much stronger security to their web application and would like you to test whether the pattern by which the session IDs are being generated could be determined by an attacker. 
    
    - From Burp Repeater, manually change the security level from Medium to High:
    
      - Change `security=medium` to `security=high`.
    
    - Now press the Send button again and observe how the session ID has changed in the HTTP response, to 32 characters:
    
      - Here is a sample: `Set-Cookie: dvwaSession=c4ca4238a0b923820dcc509a6f75849b`.
    
    - Now press the Send button again and observe how the session ID has changed in the HTTP response to a different 32 characters:
    
      - Here is a sample: `Set-Cookie: dvwaSession=c81e728d9d4c2f636f067f89cc14862c`.    
    
    - Continue to press Send to observe how the session IDs change each time.   
    
    - As a security analyst, you are tasked with determining whether the formula or method for generating each session ID can be predicted.     
    
      - **Hint**: Note the length of the session ID.
    
    - Document the method used to generate these session IDs.
      
    - **Solution**
    
      - The DVWA session IDs generated are actually the same as the low-level security (incrementing by 1), with the following exception:

        - After they increment by 1, they are hashed by the MD5 algorithm.
      
          - This is why each session ID is 32 characters (the length of the MD5 algorithm).
          
        - For example:

          - `1` >>  MD5 HASH >>>  c4ca4238a0b923820dcc509a6f75849b

          - `2` >>  MD5 HASH >>>  c81e728d9d4c2f636f067f89cc14862c
          
          - `3` >>  MD5 HASH >>>  eccbc87e4b5ce2fe28308fd9f2a7baf3
          
          - `4` >>  MD5 HASH >>>  a87ff679a2f3e71d9181a67b7542122c
  
___

© 2021 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
