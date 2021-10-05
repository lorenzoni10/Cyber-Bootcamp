## Solution Guide: Generating Hashes

The goal of this exercise was to use hashes to validate the integrity of data.  You were tasked with generating MD5 hashes to determine which files were modified.

---

- Extract the investigation summary files.

- Navigate to the backup directory:

  - Run `cd /Alphabet_Bandit_Investigation_Reports/backup`
         
- Create a single hash file for all of the files:

  - `md5sum * > hashes`
      
- Preview the hash file:

    - `more hashes`
      
- The file should look like:

  ```    
  94d53dff0ba90e465fcf1e7b900ec843 *Investigation_1101
  abf9816ba8e141b301848e09038ed1f8 *Investigation_1108
  3edab292de508c37fc8aeb5fd973d54b *Investigation_1110
  609c6b71a2241e1b8f878c682d138c2d *Investigation_1112
  2147a20472c421f2b9af8250d742bbd1 *Investigation_1116
  ```

- Copy the hash file to the `current` folder:

   - `mv hashes ../current/`
    
- Navigate to the `current` folder:

  - `cd ..`
  - `cd current`
      
- Run the following command to compare the hashes from the backup folder and the current folder:

  - `md5sum -c hashes`
      
- The results should clearly show the two files are different (`Investigation_1101` and `Investigation_1110`):
 
  ```
  Investigation_1101: FAILED
  Investigation_1108: OK
  Investigation_1110: FAILED
  Investigation_1112: OK
  Investigation_1116: OK
  md5sum: WARNING: 2 computed checksums did NOT match
  ```
          
- Next, since we know which two files were modified, run the following `diff` commands to find out what was changed:

  - `diff Investigation_1101 ../backup/Investigation_1101`
  - `diff Investigation_1110 ../backup/Investigation_1110`
           
- The results should show:

  - `1101`:
      ```
      < Dr Browns Residence was burglarized, exotic car was taken as well as several containers of Plutonium.
        ---
      > Dr Browns Residence was burglarized, exotic car was taken as well as several containers of Gasoline
      ```
  - `1110`

    ```
      < Jennifer Parkers House was burglarized, mostly jewelry was stolen and significant damage occurred at the house
        ---
      > Jennifer Parkers House was burglarized, mostly jewelry was stolen and no damage occurred at the house
    ```      

- These outputs show the following changes:

  - In the `1101` file, the word  `Plutonium` was changed to `Gasoline`.
  
  - In the `1110` file, the word  `significant` was changed to `no`.

  ---
   © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
