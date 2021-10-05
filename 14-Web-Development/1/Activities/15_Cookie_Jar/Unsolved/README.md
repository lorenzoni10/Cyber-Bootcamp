## Activity File: The Cookie Jar

In this activity, you will continue in your role as a  web app security engineer.

- Your company has evaluated your findings of WordPress's usage of year-long cookies as an acceptable risk. Your next phase of testing requires you to explore how to test cookie functionality with `curl`.

- You are tasked with using the command-line tool, `curl` to continue testing session cookies within WordPress accounts.


### Instructions

Using `curl`, you will do the following for the Ryan user:

  - Log into WordPress and save the user's cookies to a "cookie jar."

  - Test a WordPress page by using a cookie from the cookie jar.

  - Pipe the output from the cookie with `grep` to check for proper page access.

  - Attempt to access a privileged WordPress admin page.

#### Set Up

Create two new users: Amanda and Ryan.   

  - Navigate to `localhost:8080/wp-admin/`
  - On the left-hand toolbar, hover over **Users** and click **Add New**.
  - Enter the following information to create the new user named Amanda.
    - Username: `Amanda`
    - Email: `amanda@email.com`
  
  - Skip down to password:
    - Password: `password`
    - Confirm Password: Check the box to confirm use of weak password.
    - Role: `Administrator`

- Create another user named Ryan.
    - Username: `Ryan`
    - Email: `ryan@email.com`

- Skip down to password:
    - Password: `123456`
    - Confirm Password: Check the box to confirm use of weak password.
    - Role: `Editor`

- Log out and log in with the following credentials:
  - Username: `Amanda`
  - Password: `password`


#### Baselining

1. Using your browser, log into your WordPress site as your sysadmin account and navigate to `localhost:8080/wp-admin/users.php`, where we previously created the user Ryan. Examine this page briefly. Log out.

2. Using your browser, log into your Ryan account and attempt to navigate to `localhost:8080/wp-admin/index.php`. Note the wording on your Dashboard.

3. Attempt to navigate to `localhost:8080/wp-admin/users.php`. Note what you see now.

Log out in the browser.

#### Using Forms and a Cookie Jar

4. Navigate to `~/Documents/wp` in a terminal.

5. Construct a `curl` request that enters two forms: `"log={username}"` and `"pwd={password}"` and goes to `http://localhost:8080/wp-login.php`. Enter Ryan's credentials where there are placeholders.

    - **Question:** Did you see any obvious confirmation of a login? (Y/N)

6. Construct the same `curl` request, but this time add the option and path to save your cookie: `--cookie-jar ./ryancookies.txt`. This option tells `curl` to save the cookies to the `ryancookies.txt` text file.

7. Read the contents of the `ryancookies.txt` file.

    - **Question:** How many items exist in this file?

Note that each one of these is a cookie that was granted to Ryan after logging in.

#### Log in Using Cookies

8. Craft a new `curl` command that now uses the `--cookie` option, followed by the path to your cookies file. For the URL, use `http://localhost:8080/wp-admin/index.php`.

    - **Question:** Is it obvious that we can access the Dashboard? (Y/N)

9. Press the up arrow on your keyboard to run the same command, but this time, pipe `| grep Dashboard` to the end of your command to return all instances of the word `Dashboard` on the page.

    - **Question:**  Look through the output where `Dashboard` is highlighted. Does any of the wording on this page seem familiar? (Y/N) If so, you should be successfully logged in to your Editor's dashboard.

#### Test the `Users.php` Page

10. Finally, write a `curl` command using the same `--cookie ryancookies.txt` option, but attempt to access `http://localhost:8080/wp-admin/users.php`.

    - **Question:** What happens this time?


---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  