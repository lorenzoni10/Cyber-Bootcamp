## Activity File: Removing Windows Bloat with PowerShell Scripts

- In this activity, you will be continuing your role as a junior system administrator. 

- As a system administrator, we don't want our users playing games or using unnecessary applications while working. One reason is that these applications can potentially expose personal user email addresses, usernames, or other personal identification information to unnecessary applications.

- The CIO has tasked us with creating a PowerShell script that will get rid of these Windows bloat applications, and has provided a CSV file containing a list of these application's packages. 

  - Note that this list is significantly larger than in the demo.

Use the following directory and CSV file within your **Windows RPD Host machine** to complete the activity: 

- Use `C:\Users\azadmin\Documents\Activity\choco` as your working directory.

- Use the `chocoactivity.csv` inside this directory for your activity.

### Instructions

1. Create a PowerShell script file called `removepackages.ps1` in the working directory given above.

    - The file can be tested with `.\removepackages.ps1` in PowerShell.

    - Use the following template to set up your script:

        ```PowerShell
        <import line here>
        foreach (<condition here>) {
            <PowerShell code block to be executed here>
        }
        ```

2. Import the CSV `chocoactivity.csv` by assigning the `$csv` variable to the `Import-Csv` cmdlet, with the appropriate parameters.

3. Create a `foreach` condition where a `$package` variable reads each line in the `$csv` variable.

4. Within the code block, run the uninstall command with the appropriate variable and attribute.

   - Make sure to include the auto-confirm parameter that stands for `yes`.

   -  When you successfully create and execute the script, PowerShell will start uninstalling the packages within the CSV file. This will take a few minutes to complete.

#### Bonus

4. Under the get and remove cmdlet pipeline, print a line that states `<package name> removed!` using the proper CSV field instead of the placeholder.

  - **Hint**: If you're not sure what fields exist in the CSV file, open it!

#### Reinstalling your Applications

Simply change "uninstall" to "install" within your code block to reinstall the applications for repeated testing. This will take a few minutes to complete.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
