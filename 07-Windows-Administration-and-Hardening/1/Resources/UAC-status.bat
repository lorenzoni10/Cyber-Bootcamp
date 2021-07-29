@echo off

    reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" | find  "0x0" >NUL
    if "%ERRORLEVEL%"=="0"  ECHO UAC disabled
    if "%ERRORLEVEL%"=="1"  ECHO UAC enabled
::    pause

::    exit