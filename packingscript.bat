 @echo off
rem go to directory where cmd script is
cd %~dp0
rem check for 7z.exe
rem todo : allow for an environment variable that defines location of 7zip
if not exist "c:\program files\7-zip\7z.exe" goto need7zip
rem cut up date and time to use for backup filename
set CUR_YYYY=%date:~0,4%
set CUR_MM=%date:~5,2%
set CUR_DD=%date:~8,2%
set CUR_HH=%time:~0,2%
if %CUR_HH% lss 10 (set CUR_HH=0%time:~1,1%)
set CUR_MI=%time:~3,2%
set CUR_SS=%time:~6,2%
set CUR_MS=%time:~9,2%
rem rename zip file for safe keeping
rename aws-landing-zone-configuration.zip aws-landing-zone-configuration_%CUR_YYYY%%CUR_MM%%CUR_DD%_%CUR_HH%%CUR_MI%%CUR_SS%-bak.zip
cd aws-landing-zone-configuration
"c:\program files\7-zip\7z.exe" a -r -x!*.bak ..\aws-landing-zone-configuration.zip *
if errorlevel 1 goto zipError
goto end
:need7zip
echo 7zip is either not installed or not found at c:\program files\7-zip
rem pause
goto end
:zipError
echo.
echo ERROR zipping config file
echo See messages above
rem pause
goto end
:end
pause