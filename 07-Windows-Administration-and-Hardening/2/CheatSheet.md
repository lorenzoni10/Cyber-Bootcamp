## 7.2 CheatSheet: Common PowerShell Commands

| Cmdlet          | Function                                         | Equivalent Command     |
| --------------- | ------------------------------------------------ | ---------------------- |
| `Set-Location`  | Changes to specified directory                   | `cd`                   |
| `Get-ChildItem` | Return current directory contents                | `ls`, `dir`            |
| `New-Item`      | Makes a new file or directory                    | `touch`, `mkdir`       |
| `Remove-Item`   | Deletes a file or directory                      | `rm`, `rmdir`          |
| `Get-Location`  | Retrieves path to current directory              | `pwd`                  |
| `Get-Content`   | Returns file contents                            | `cat`, `type`          |
| `Copy-Item`     | Copies a file from one given location to another | `cp`                   |
| `Move-Item`     | Moves a file from one given location to another  | `mv`                   |
| `Write-Output`  | Prints output                                    | `echo`                 |
| `Get-Alias`     | Shows aliases for the current session           | `alias`                |
| `Get-Help`      | Retrieves information about PowerShell commands  | `man`                  |
| `Get-Process`   | Gets processes running on local machine          | `ps`                   |
| `Stop-Process`  | Stops one or more defined processes            | `kill`                 |
| `Get-Service`   | Gets a list of services                          | `service --status-all` |

### How to Use Documentation and Find Commands

To find documentation on a cmdlet:

- `Get-Help {cmdlet}`

  - For example: To find documentation on `Set-Location`:

     - `Get-Help Set-Location`

To find specific examples:

- `Get-Help {cmdlet} -examples`

To find cmdlets by noun:

- `Get-Command -Type Cmdlet | Sort-Object -Property Noun | Format-Table -GroupBy Noun`

To find cmdlets by verb:

- `Get-Command -Type Cmdlet | Sort-Object -Property Verb | Format-Table -GroupBy Verb`

#### Wildcards

To find by noun:

- `Get-Command -Noun {noun}`

To find by verb:

- `Get-Command -Verb {verb}`

#### Chocolatey

To install a package:

- `choco install <package>`

  - Use the `-y` parameter to auto-confirm

  - `choco install -y <package>`

To uninstall a package:

- `choco uninstall <package>`

  - Use the `-y` parameter to auto-confirm

  - `choco uninstall -y <package>`

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
