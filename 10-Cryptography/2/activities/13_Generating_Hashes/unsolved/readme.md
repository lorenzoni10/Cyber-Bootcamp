## Activity File: Generating Hashes

In this activity, you will continue to be a security analyst working for the Hill Valley Police department.

- Captain Strickland believes that the Alphabet Bandit, who is likely an insider, has been changing the investigation report files to throw off the investigation.

- Fortunately, the Hill Valley Police Department has backup files of all the investigation reports.

- Captain Strickland would like you to determine if any investigation report files have been changed, as well as _what_ was changed.

- Your task is to generate hashes of each backup and current file and compare the hashes to determine which files were changed.

- You must then use command-line tools to determine the changes made to those files.

### Instructions:

1. Extract the investigation files provided to you.

  - Note that there are directories titled `current` and `backup`, each of which contain the investigation report files.

     - It's quite likely that the Alphabet Bandit modified the data in the current files.

2. Use `md5sum` to generate hashes of all the files into a single file called `hashes`.

3. Compare the hashes with a single `md5sum` command to determine which of the files were changed in the `current` directory.

4. Use the `diff` command to figure out what was changed in the modified files.

--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


  
