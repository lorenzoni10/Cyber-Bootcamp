## Solution Guide: Removing Windows Bloat with PowerShell

For this exercise, we used conditionals in a PowerShell script to uninstall various Windows packages that add bloat to the system and increase the attack surface of the system. 

#### Solution 

1. Create a PowerShell script file called `removepackages.ps1` in the working directory.


    - Run `cd C:\Users\azadmin\Documents\Activity\choco`

    - Create a `removepackages.ps1` file:

        - Create a file in your preferred text editor and save it as `removepackages.ps1`.

2. Import the CSV `chocoactivity.csv` by assigning the `$csv` variable to the `Import-Csv` cmdlet, with the appropriate parameters.

    - We'll need a line for importing the CSV file:

        - Type `Import-Csv -Path ./chocoactivity.csv`

           

3. Create a `foreach` condition where a `$package` variable reads each line in the `$csv` variable.


    - Start a PowerShell `foreach` loop template:

        ```PowerShell
        foreach () {

        }
        ```

    - Construct the `foreach` condition within the parentheses.

    - Enter `$package in $csv` in the parentheses.

4. Within the code block, run the uninstall command with the appropriate variable and attribute.


    - Enter `choco uninstall -y $package.name` in the code block.


5. For the bonus, add the following line: `Write-Output $package.name removed!`.

    - Your final script should look like this:

        ```PowerShell
        $csv = Import-Csv -Path .\chocoactivity.csv
        foreach ($package in $csv) {
            choco uninstall -y $package.name
            Write-Output $package.name removed!
        }
        ```

When we successfully create and execute the script, PowerShell will start uninstalling the packages within the CSV file. This will take a few minutes to complete.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.