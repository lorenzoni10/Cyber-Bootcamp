# Day 3 Cheat Sheet - Unit-Terminal

## Key Terms

- **Shell**: The shell is the program used to interpret and manage commands. It is the operating system command line interface (CLI) and provides a way to create and execute scripts.  
  - **Example**: The *bash* shell which stands for Bourne Again Shell is included in most Unix distributions.

- **Shell Script**: A shell script is a text file consisting of commands that are stored and run.  Shell scripting is a powerful tool to use because it allows IT and security professionals to prescript repeatable processes for future use. Shell scripts have the extension *.sh*
  - **Example**: `script.sh`
  
 ```bash 
    # Create a folder called Summary
    mkdir Summary

    # Combine all files in the Files folder into a single file called MySummary.txt
    cat Files/*.txt > MySummary.txt

    # Move the MySummary.txt file into the Summary folder.
    mv MySummary.txt Summary

    # Preview the contents
head Summary/MySummary.txt
```

-------

## Copyright

Trilogy Education Services © 2019. All Rights Reserved.
