## Solution Guide: The Cookie Jar

The goal for this activity was to quickly familiarize you with using `curl` to save and use cookies.

Security roles that deal with testing websites will need to know how to leverage command-line cookies for scripting and automation in their work.

#### Walkthrough

Using `curl`, you had to do the following for the Ryan user:

  - Log into WordPress and save the user's cookies to a "cookie jar."

  - Test a WordPress page by using a cookie from the cookie jar.

  - Pipe the output from the cookie with `grep` to check for proper page access.

  - Attempt to access a privileged WordPress admin page.

#### Baselining

The goal of the baselining portion of this activity was to get you familiar with the contents of the Dashboard and what `users.php` looked like for both Administrator and Editor users. 

  The later parts of the activity checked to see if `curl` returned these same pages.

#### Using Forms and a Cookie Jar

Construct a `curl` request that enters two forms: `"log={username}"` and `"pwd={password}"` and goes to `http://localhost:8080/wp-login.php`. Enter Ryan's credentials where there are placeholders:

- `curl --form "log=Ryan" --form "pwd=123456" http://localhost:8080/wp-login.php` 

- **Question:** Did you see any obvious confirmation of a login? (Y/N)

    - **Answer:** There was no obvious notification of login.

Construct the same `curl` request, but this time add the option and path to save your cookie: `--cookie-jar ./ryancookies.txt`. This option tells `curl` to save the cookies to the `ryancookies.txt` text file:

- `curl --cookie-jar ./ryancookies.txt --form "log=Ryan" --form "pwd=123456" http://localhost:8080/wp-login.php`

 - **Question:** How many items exist in this file?
    - **Answer:** Four cookies exist in the `ryancookies.txt` file.

#### Log in Using Cookies

Craft a new `curl` command that now uses the `--cookie` option, followed by the path to your cookies file. For the URL, use `http://localhost:8080/wp-admin/index.php`:

- `curl --cookie ./ryancookies.txt http://localhost:8080/wp-admin/index.php` 

- **Question:** Is it obvious that we can access the Dashboard? (Y/N)
    
    - **Answer:** It doesn't seem obvious at first that we can access the Dashboard.


Press the up arrow on your keyboard to run the same command, but this time, pipe `| grep Dashboard` to the end of your command to return all instances of the word `Dashboard` on the page:

- `curl --cookie ./ryancookies.txt http://localhost:8080/wp-admin/index.php | grep Dashboard`

- **Question:** Look through the output where `Dashboard` is highlighted. Does any of the wording on this page seem familiar? (Y/N) If so, you should be successfully logged in to your Editor's dashboard.

  - **Answer:** After adding the grep pipe, we can see all occurrences of the word `Dashboard` within the returned response body, showing us a successfully returned `index.php` session.

#### Test the `Users.php` Page

Finally, write a `curl` command using the same `--cookie ryancookies.txt` option, but attempt to access `http://localhost:8080/wp-admin/users.php`:

- `curl --cookie ./ryancookies.txt http://localhost:8080/wp-admin/users.php`

- **Question:** What happens this time?
  - **Answer:** We once again see the `You need a higher level of permission. Sorry, you are not allowed to list users.` warning page.


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
