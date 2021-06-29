## Solution Guide: Finding Your Way

- The first step is to navigate into the `/03-student/day2/finding_your_way/PeanutButtery.net/` folder on your VM. To complete this, run the following command:
 
  - `cd /03-student/day2/finding_your_way/PeanutButtery.net/`
       
- The next step is to find all directories that have the word "secret" in their name. To do this, run:

   - `find -type d -iname *secret*`
  
   
      - `find`: The command-line command.
      - `-type`: The option for specifying whether you're searching for a file or a directory.
      - `d`: The required parameter for the  `-type` option, indicating you're searching for a directory.
      - `-iname`: The option indicating you're searching for a specific case-insensitive value.
      - `*secret*`: The parameter indicating the value you're searching for. The two wildcards indicate that the value `secret` can be located anywhere in the file name.
    
    
- When you run the command, the results should return the following directory path containing the value of `secret`: `./other/disregard/wonkasecretrecipes`.
      
    - This means the directory `wonkasecretrecipes` is within the `disregard` directory, within the `other` directory.
    
- Next, we need to find the files that contain the word "recipe." The command to do this is:

  - `find -type f -iname *recipe*`
     
    - `find`: The command-line command.
    - `-type`: The option for specifying whether you're searching for a file or a directory.
    - `f`: The required parameter for the  `-type` option, indicating you're searching for a file.
    - `-iname`: The option indicating you're searching for a specific case-insensitive value.
    - `*recipe*`: The parameter specifying the value you're searching for. The two wildcards indicate that the value `recipe` can be located anywhere in the file name.    
     
- The results of the command should return the following four files that have the value of `recipe` in the name:  
     
     - `./other/disregard/wonkasecretrecipes/recipe_crunchybars`
     - `./other/disregard/wonkasecretrecipes/recipe_peanutballs`
     - `./other/disregard/wonkasecretrecipes/recipe_peanutsquares`
     - `./other/disregard/wonkasecretrecipes/recipe_yumbars`
     
- The four files are: `recipe_yumbars`,  `recipe_peanutsquares`, `recipe_peanutballs`, `recipe_crunchybars`.  

     
**Bonus**

You were asked to find files containing the words "recipe" and "peanut" in the name.

- To do this, we need to use a conditional of `-a` to add an additional search. The command is:

  - `find -type f -iname *recipe* -a  -iname *peanut*`
 
    - `find`: The command-line command.
    - `-type`: The option for specifying whether you're searching for a file or a directory.
    - `f`: The required parameter for the  `-type` option, indicating you're searching for a file.
    - `-iname`: The option indicating you're searching for a specific case-insensitive value.
    - `*recipe*`:  The parameter specifying the value you're searching for. The two wildcards indicate that the value of `recipe` can be located anywhere in the file name.      
    - `-a`: The conditional statement that represents **AND**,  which states that the next value must also be matched in the result.  
      - `-o` can be used as an **OR** conditional, returning results that include either one of the specified values.
    -  `-iname *peanut*`: The second value that needs to be found in a file name.  
  
  When you run the command, the results show two files that have the word "recipe" and "peanut" in their names:
  
     - `./other/disregard/wonkasecretrecipes/recipe_peanutballs`
     - `./other/disregard/wonkasecretrecipes/recipe_peanutsquares`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
