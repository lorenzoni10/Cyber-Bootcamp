## Solution Guide: Warm-Up


- The first step is to navigate into the `/03-student/day3/warmup` folder on your VM. To do this, run the following commands:
   - `cd /03-student/day3/`
   - `cd warmup`

- Create a folder called `subpoena_request`:

  - `mkdir subpoena_request`

- Next, find the files dated 0719. Run the following command:   

  - `find -type f -iname *0719*`

     This will return the following two files:
       ```
       ./WEBACCESS/0719Apache
       ./WEBACCESS/IIS_0719
       ```
- Move the files into the `subpoena_request` folder using a wildcard:

  - `mv ./WEBACCESS/*0719* ./subpoena_request/`

 - Find the phone records that provide proof of calls made to Slugworth's number,  454-555-3894, and place them in a file called `Calls_to_Slugworth`:

   - `grep 454-555-3894 ./PHONE_LOGS/* > Calls_to_Slugworth`

- Move the file into the `subpoena_request` folder:

  - `mv Calls_to_Slugworth ./subpoena_request/`


**Bonus**

- The following three incoming phone numbers are in the file we created called `Calls_to_Slugworth`:
  - 212-555-2732
  - 212-555-2733
  - 212-555-2734

- To look up the owners of these three phone numbers, run the following:

  -  `grep '212-555-2732\|212-555-2733\|212-555-2734' ./DIRECTORIES/*`

- The results show the the following:

       212-555-2734    Mr GoodBar  
       212-555-2732    Ruth  
       212-555-2733    Henry

  It looks like Mr. Goodbar has also been in contact with Slugworth.      

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
