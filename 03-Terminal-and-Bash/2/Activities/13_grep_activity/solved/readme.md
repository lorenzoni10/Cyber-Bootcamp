## Solution Guide: grep 

- The first step is to navigate into the folder on your VM where the recipes are located. To do this, run the following commands:
 
  - `cd /03-student/day2/`
  - `cd finding_your_way/`
  - `cd PeanutButtery.net/other/disregard/wonkasecretrecipes`

- We need to search for recipes containing the ingredient "guavaberries." The command to search for them in this directory is:

  - `grep -i guavaberries *`
     
     - `grep`: The command being run.
     - `-i`: An option for `grep` indicating case insensitivity.
     - `guavaberries`: The specific data point being searched for.
     - `*`: A wildcard, indicating the command should search through all files in the current directory. 
     
- After running the command, the results show four files containing "guavaberries":

  - `recipe_crunchybars:5 guavaberries`
  - `recipe_peanutballs:4 guavaberries`
  - `recipe_peanutsquares:8 guavaberries`
  - `recipe_yumbars:2 guavaberries`
        
 - These results show the file names of all recipes that include guavaberry as an ingredient, followed by a colon and the line in which "guavaberries" appears.    
     
     
**Bonus** 

- We will adjust the `grep` command to search for files that also contain the word "optional," indicating that the guavaberries are an optional ingredient. 

    The command to search for multiple data points in a file is:  

  - `grep -i 'guavaberries\|optional' *`
       

     - `grep`: The command being run.
     - `-i`: Option for `grep` indicating case insensitivity.
     - `guavaberries`: The first specific data point being searched for.
     - `\|`: Indicates OR. 
       - Included between values to search for multiple values using one command.
     -   `optional`: The second data point being searched for.
     - `*`: A wildcard indicating the command should search through all files in the current directory. 


-  Run the command and notice the results show all four files, but five lines contain guavaberries OR the word "optional":
         recipe_crunchybars:5 guavaberries
         recipe_peanutballs:4 guavaberries
         recipe_peanutsquares:8 guavaberries
         recipe_peanutsquares:  Note: optional - another berry that can be substituted is blueberries
         recipe_yumbars:2 guavaberries

- This shows that `recipe_peanutsquares` has an "optional" note stating that blueberries can substitute guavaberries.


- This shows that Wonka should be the most concerned about the Peanut Squares recipe, as Slugworth can make this without guavaberries.

--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
