## Activity File: Database Management

In this activity, you will play the role of a junior web engineer for the GoodCorp, Inc. company and will be managing their web application.

- GoodCorp, Inc. uses Docker Compose and a set of containers to deploy and maintain its employee database website and application.

- You are tasked with locally deploying GoodCorp's employee directory web site with Docker Compose and will need to manage the data inside of the employee directory database.

---

### Resources

:books: Use the following W3Schools references if you need help during this activity:

- [SQL SELECT Statement](https://www.w3schools.com/sql/sql_select.asp)
- [SQL WHERE Clause](https://www.w3schools.com/sql/sql_where.asp)
- [SQL INSERT Statement](https://www.w3schools.com/sql/sql_insert.asp)
- [SQL DELETE Statement](https://www.w3schools.com/sql/sql_delete.asp)

### Instructions

1. First, deploy the container set using Docker Compose:

    - Navigate to your `/home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_databases` directory. 

    - Set up the database with `./reset_databases.sh`.

      - **Note**: if you enter the wrong query or mess up the database, you can re-run this script to reset it.

    - Deploy the container stack with `docker-compose up`.

    - Verify the site is running by navigating to `localhost:10005` in the browser.

2. Find the MySQL credentials in the `/home/sysadmin/Cybersecurity-Lesson-Plans/14-Web_Dev/deploying_databases` compose file.

3. Enter an interactive bash session in the database's container. The container name can also be found in the compose file.

4. Within the interactive bash session, use the credentials found earlier to enter a MySQL session using the `goodcorpdb` MySQL database.

5. Create a basic `SELECT` query to find all of the employee table entries in the `goodcorpdb` database.

6. Using the given information, create a query to add the following new user to the employee directory:

    - **First name**: Fran
    - **Last name**: Frappucino
    - **Email Address**: ffrappucino@goodcorp.net
    - **Department**: Finance

7. Create a modified `SELECT` query to find all employees in the Research and Development department.

8. Create a `DELETE` query to remove the entry for Bob using his ID number.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.