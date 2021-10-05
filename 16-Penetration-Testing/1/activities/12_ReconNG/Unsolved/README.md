## Activity File: Recon-ng

In this activity, you will continue your work for SecureWay.

- You've been tasked with working with a client, rapid7.com, to discover if their domain server info is accessible using OSINT tools.

- You will use the Shodan API and Recon-ng to perform your tests, and then place all of your findings in a report.
 
### Instructions
 
1. In Kali, log in with the credentials `root:toor` and start Recon-ng.
 
2. Set an API key for modules that require it.
 
   - We'll set a Shodan API key inside Recon-ng to allow Recon-ng to display results from the Shodan API.
 
   - If you haven't done so already, go to shodan.io and register for a free account. 
      - Once registered, click on **My Account** in the top-right corner and copy the API key to your clipboard.
 
3. In Recon-ng, type the command to view all of the currently installed modules.
 
   - For this activity we'll use the following three modules:
 
     - `recon/domains-hosts/hackertarget`
     - `recon/hosts-ports/shodan_ip`
     - `reporting/html`

4. Before you begin, install the modules that you will need. 

   - Using the command `marketplace install` install the `reporting/html` module

5. Type the command that will load the `shodan_ip` scanner module.
 
   - Remember, modules need to be loaded prior to use.
   - Type the command that adds your API key.
 
6. Type the command that verifies the API key was successfully imported.
 
7. Type the command that displays more information about the Shodan module.
 
   - The `SOURCE` option is required. Type the command that sets the `SOURCE` to rapid7.com.
 
      - The `SOURCE` option specifies which target Recon-ng will scan.
 
8. Type the command that runs the query.
 
   - Recon-ng will query Shodan for a scan against rapid7.com.
   - The results will automatically display verbosely in the terminal window.
 
9. Type the command that selects and loads the reporting module.

10. Type the command that shows which parameters need to be set.
 
   - The `CREATOR` and `CUSTOMER` parameters need to be set.
 
   - Set the parameters as follows:
   
      - `CREATOR`: Pentester
      - `CUSTOMER`: Rapid7
 
   - Type the command that runs the query so the results are saved to `/root/.recon-ng/workspaces/default/results.html`.
    
   - Type the command that verifies whether the configuration took effect after setting the options.
 
11. View the report.

    - Generate the report so it can be viewed as HTML in the web browser.

    - How many hosts did Recon-ng discover?
 
 
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
