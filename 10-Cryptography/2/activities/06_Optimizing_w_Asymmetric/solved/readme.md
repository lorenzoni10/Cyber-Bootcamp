## Solution Guide: Optimizing with Asymmetric Public Keys

The goal of this activity was to compare key distribution and the number of required keys for asymmetric encryption and symmetric encryption. 

You calculated how many symmetric and asymmetric keys are needed depending on the number of people exchanging secure messages.

---

- The key formulas for calculating the number of keys required: 

     - Symmetric encrytion: **(N * (N-1)) / 2** 
     - Asymmetric encryption: **N * 2** 
                
     **In both formulas, N = the number of individuals.** 

- To calculate for the SWAT team, with 10 officers:

     - Symmetric: (10 * 9)/2  = 45
     - Asymmetric: 10 * 2   = 20
     - Difference: 45  - 20 = 25

- To calculate for the Canine Unit, with 25 officers:

     - Symmetric: (25 * 24)/2 = 300
     - Asymmetric: 25 * 2 = 50
     - Difference: 300 - 50 =  250

- To calculate for Internal Affairs, with 45 officers:

     - Symmetric: (45 * 44)/ 2 = 990
     - Asymmetric: 45 * 2    = 90
     - Difference: 990 - 90 = 900

- The final summary:

    - The SWAT team will need 25 fewer keys after moving from symmetric to asymmetric cryptography.

    - The Canine Unit will need 250 fewer keys after moving from symmetric to asymmetric cryptography.

    - Internal Affairs will need 900 fewer keys after moving from symmetric to asymmetric cryptography.

---
 © 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
