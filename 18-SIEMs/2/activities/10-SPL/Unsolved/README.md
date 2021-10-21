## Activity File: SPL Search

- As the SOC manager at OMP, you are asked to analyze the company's vulnerability scanning logs in order to determine the vulnerabilities of OMP's technical assets. 

- To accomplish this, you must design SPL searches to run against the vulnerability scanning log file `nessus.txt`.

- These searches can be used to quickly look up existing vulnerabilities on your operating systems or devices.

### Instructions

1. Using SPL, design searches to display the following data from the `nessus` logs:

    - Display results where OS contains "Windows".

    - Display results where OS contains "Linux".
    
    - Display results where `dest_ip` is `10.11.36.4`.
    
    - Display results where `dest_ip` starts with `10.12.34`.
      - **Hint:** Use wildcards in your searches.

2. Run your designed queries within Splunk and determine the count returned for each query.

#### Bonus

- Design an SPL search to display results where the signature contains an RDP man-in-the-middle weakness.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  