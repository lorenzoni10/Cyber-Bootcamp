## Solution Guide: Creating a Report with wmic Output

This activity introduced you to using the `wmic` process in the command line. 

#### Solution

1. Begin by listing all the different values that can be retrieved from the `os` `wmic` alias:

    - Run `wmic os get /value`

    - We can see (in the Caption property) that the operating system edition is `Microsoft Windows 10 Pro`.

    - We can also see the `BuildNumber` is `18362`.

    Next, append this info to our `report.txt` file:

    - Run `wmic /APPEND:report.txt os get caption, buildnumber`

      ```console
      BuildNumber  Caption
      18362        Microsoft Windows 10 Pro
      ```

2. Create a `wmic` query for each of the following aliases and append them to the report:

    - All user info, SID, important directories, and files:

      - Run `wmic /APPEND:report.txt useraccount get name, sid, description`

        ```
          Description                                                    Name                SID
          Built-in account for administering the computer/domain        Alex                 S-1-5-21-4186057849-1686307938-2621843307-1000

                                                                        azadmin              S-1-5-21-4186057849-1686307938-2621843307-500

          A user account managed by the system.                         DefaultAccount       S-1-5-21-4186057849-1686307938-2621843307-503

          Built-in account for guest access to the computer/domain      Guest                S-1-5-21-4186057849-1686307938-2621843307-501
                                                                        
          A user account managed and used by the system ...[truncated]. WDAGUtilityAccount   S-1-5-21-4186057849-1686307938-2621843307-504
        ```

      - **Note**: The SID is the Security Identifier of an account. The `S-1-5` portion essentially states that it is a Windows-based Security Identifier, version 1. 

      - The next part of the SID before the last set of numbers is the domain or local computer identifier, in this case: `21-4186057849-1686307938-2621843307`. 
      
      - The last number of the SID is the `Relative ID`, which is much like a `UID` or "user identifier" in Linux. `Relative IDs` below `1000` are built-in accounts, such as the `Guest` account. And any `RID` equaling `1000` or higher is for non-built-in user accounts, such as `Alex`.

      - You'll notice that the `azadmin` account has a `RID` of `500`. `500` is the built-in user account reserved for the local system administrator, which has full control rights over the system. 

      - :books: To learn more about SIDS, refer to the following:  
      
        - [Microsoft | Support: Well-known security identifiers in Windows operating systems](https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems).

    - The number of times all users have logged on, and last logon:

        - Run `wmic /APPEND:report.txt netlogin get caption, numberoflogons, lastlogon`

          ```
          Caption                       LastLogon                  NumberOfLogons
          NT AUTHORITY\SYSTEM
          NT AUTHORITY\LOCAL SERVICE
          NT AUTHORITY\NETWORK SERVICE
          azadmin                      20200821153032.000000+000  28
          ```

    - Windows update information:

      - Run `wmic /APPEND:report.txt qfe get caption, description, installedon, hotfixid`

          ```
        Caption                                     Description      HotFixID   InstalledOn
        http://support.microsoft.com/?kbid=4532938  Update           KB4532938  2/9/2020
        http://support.microsoft.com/?kbid=4513661  Update           KB4513661  2/9/2020
        http://support.microsoft.com/?kbid=4537759  Security Update  KB4537759  2/9/2020
        http://support.microsoft.com/?kbid=4538674  Security Update  KB4538674  2/9/2020
        http://support.microsoft.com/?kbid=4532693  Update           KB4532693  2/9/2020
          ```

Verify the report by running `type report.txt`. 

----

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
