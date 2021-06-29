## Solution Guide: Oh Henry, What Did You Do?  
 
 - The first step is to navigate into the `students/oh_henry` folder on your VM. To do so, run the following command: 
   - `cd /03-student/day1`

- Navigate to Henry's Folder:
   - `cd oh_henry`
         
- There are many files in this directory. You can preview each file by using `head`, `more`, or `less`. For example:
  - `head do.txt`

  or
 
  - `more do.txt`

- Most of the files contain non-ASCII data, as they are actually image files.

- The three files that contain text data are:   

  - Henry:   `do.txt sp.txt wp.txt`  
  - Ruth:    `l8.txt hy.txt ud.txt`

- Delete the other files: 

  - `rm dj.txt bb.txt b7.txt sd.txt ta.txt`  

- Confirm that only the correct files remain by running:
 
  - `ls`
  
  - The three files that should remain: `do.txt sp.txt wp.txt`

- Complete this same process in Ruth's folder.  
  - The files that should remain: `l8.txt  hy.txt ud.txt`
    
**Bonus**

- To view the date on the bottom of each file, run:

  - `tail do.txt`
     
- On the bottom of the file called `do.txt` is the date October 10, 2019. To rename this file, run:

  - `mv do.txt do.txt_10_13_2019`
     
- Follow this same process for all the files. 
The final results for Henry:
   - `do.txt_10_13_2019`
   - `sp.txt_10_14_2019`
   - `wp.txt_10_15_2019`
   
- The final results for Ruth:
   - `l8.txt_10_13_2019`
   - `hy.txt_10_14_2019`
   - `ud.txt_10_15_2019`

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
