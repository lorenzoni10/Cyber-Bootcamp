@echo off
set size=0
for /r %%x in (System\*) do set /a size+=%%~zx
echo %size% Bytes