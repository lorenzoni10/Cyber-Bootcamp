## Terminal Day 2: Cheat Sheet 

### Key Terms

- **Command Line Structure**: The structure for a command line is `command` followed by one or more `options` and one or more `arguments` (if required).
- **Example**: `find -name contacts.txt`
    * `find` is the `name of the command`
    * `-name` is the `option` (find by name)
    * `contacts.txt` is the `argument` (file to find)
     
- **find Command**: The `find` command finds all directories and files in and below the current  directory.  
    - **Example**: This command will find all files with the extension `.txt`.
        *  `$ find -type f -name '*.txt`

**Execute a command using the `find`command**: The `find` command can be used to execute a command (e.g., cp, mv, echo) on any files that are found. The command syntax is:
`find option argument -exec command {} \;` where:
- **option** is a `find` option (e.g. -iname)
- **argument** is the filename(s)
- **exec option** - `exec`
- **command** is a unix command (e.g., cp, mv)
- **{}** indicates where in the command line to read in each file found
- **\;** ends the line (the `\` escapes the `;`)
**Example**: `find` all files and then output the text `I found file  {file path}`
     *  `$ find -type f -exec echo "I found file" '{}' \; | more`
     * I found file ./tmp/tempfile 

**grep Command**: Use the `grep` command to `search inside text files` for specific text.  `grep` can be used to search a single file or a whole directory of files. By default searches are case-sensitive but case-insensitive searches can be done as well.
The command syntax is: grep [`option(s)`] pattern [`file(s)`]. 
 - **Example**: This command will `grep` (search) for the word `webmin` `/etc/services` file.
    * `$ grep webmim /etc/services`

**wc Command**: The `wc` command is used to `count` the number of `lines`, `words` and `characters` in a text file. The command syntax is wc [`options`] [`file_name(s)`]. 
 - **Example**: This command outputs the number of lines, words and characters in the file `index.html`
    * `$ wc index.html`

----
    
## Key Commands

## Operations on files

 
### find Command


#### Display instructions for the find command

```bash
$ man find
```

#### Find all the files and directories in the current tree  

```bash
$ find
```

#### List files in a specific directory

```bash
$ find ./demo
```

#### Find a file by name (case sensitive) in the current directory

```bash
$ find  . -name index.html
```

#### Find a file by name (not case sensitive)

```bash
$ find  . -iname index.html
```

#### Find all files in a directory

```bash
$ find  -type f
```

#### Find all directories

```bash
$ find  -type d 
```

#### Find all the .txt files

```bash
$ find -type f -name '*.txt'
```

#### Find directories that begin with Demo

```bash
$ find -type d -name 'Demo*'
```

#### Find files that are over 5MB in size

```bash
$ find ~/joe -size +5M
```

#### Find files before or after a creation time

```bash
$ find ~/joe -size +5M
```

#### Find files before or after a creation time

```bash
$ find . -cmin +2
```

#### Find all html files and copy them to the directory /joe

```bash
$ find . -name '*.html' -exec cp '{}' ~/joe/ \;
```

### grep Command

#### Display instructions for the grep command

```bash
$ man grep
```

#### grep (search) for the word "http" in the file index.html

```bash
$ grep http index.html
```

#### grep (search) for the word "http" in the files file1.html file2.html file3.html

```bash
$ grep http file1.html file2.html file3.html
```

#### grep (search) recursively for the word "http" in all files in a directory tree

```bash
$ grep -r http 
```


#### grep (search) for the word 'inet' from the output of the "ip addr show" command

```bash
$ ip addr show | grep inet

```

#### grep (search) for the word 'Master' ignoring case

```bash
$ grep -i Master
```

### wc Command

#### Display instructions for the wc command

```bash
$ man wc
```

#### Display the number of lines, words and characters in the index.html file

```bash
$ wc index.html
```

#### Display the count for all of the text files within a directory

```bash
$ wc . *
```

-------

## Copyright

Trilogy Education Services © 2019. All Rights Reserved.
