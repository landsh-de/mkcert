@echo off & SETLOCAL & SETLOCAL ENABLEDELAYEDEXPANSION & CLS

REM :: Resource-Patcher (ResPatch.bat)
REM :: Version 1.9 by Veit Berwig in 07/2021
REM ::
REM :: -- Dependencies --
REM ::    - Resourcer.exe
REM ::    - Admin-Rights
REM ::
REM :: -- ChangeLog --
REM ::
REM ::
REM :: -- ToDo --
REM ::
REM :: "Resourcer" Name- and Type-Codes for commandline execution in
REM :: batch-mode (see below in script). In order to get the other
REM :: codes, launch "Resourcer" in GUI-mode (without command-options)
REM :: and load an example-exe. Here you may get the codes in the
REM :: provided filename, when you try to export a resource.
REM ::
REM :: Cursor Sub-Image 1
REM :: Bitmap Data      2
REM :: Icon Sub-Image   3
REM :: Menu             4 		
REM :: Dialog           5 		
REM :: StringTable      6 		
REM :: FontDirectory    7 		
REM :: Font             8 		
REM :: Accelerator      9 		
REM :: RCData           10 		
REM :: MessageTable     11 		
REM :: Cursor Directory 12 	"Cursor", "Cursordir", "Cursorgroup"
REM :: Icon Directory   14 	"Icon", "Icondir", "Icongroup"
REM :: Version          16 		
REM :: DlgInclude       17 		
REM :: PlugAndPlay      19 		
REM :: Vxd              20 		
REM :: CursorAnimated   21 		
REM :: IconAnimated     22 		
REM :: Html             23 		
REM :: Manifest         24 		
REM :: ToolBar          241 		
REM :: Custom           -1 		
REM :: Unknown          0 	

REM :: SET DIMENSIONS
REM :: No scroll-buffer visible, when lines are defined
REM :: lower than vertical visual limit:
REM :: mode >nul 2>&1 && mode con cols=120 lines=40
mode >nul 2>&1 && mode con cols=120 lines=9999
color 1E

REM :: I myself and no one else :-)
set SCRIPTNAME=ResPatch.bat
set INIFILE=ResPatch.ini

REM :: Configuration BLOCK ##################################### BEGIN
set TARGET=mkcert.exe
set TARGETICON=res\icon.ico
set TARGETVERSION=res\version.bin
set TARGETMANIFESTA=res\manifest_admin.bin
set TARGETMANIFESTI=res\manifest_invoker.bin
set RESHACKER=tools\Resourcer.exe
REM :: Configuration BLOCK ##################################### END

echo.
echo.#####################################################################
echo.# %SCRIPTNAME%
echo.#####################################################################

REM :: relative path to absolute path -DRIVE-
set drive=%~d0
set drivep=%drive%
If $#\#$==$#%drive:~-1%#$ set drivep=%drive:~0,-1%
set drivename=%drivep%
REM :: relative path to absolute path -PATH-
set pathn=%~p0
set pathp=%pathn%
If $#\#$==$#%pathn:~-1%#$ set pathp=%pathn:~0,-1%
set pathname=%pathp%
REM :: Combining PATHs
set HOMEDRIVE=%drivename%
set HOMEPATH=%pathname%
set EXEDIR=%HOMEDRIVE%%HOMEPATH%
set DIRCMD=/O:GNE

REM :: Extend PATH for using busybox functions:
set PATH=%EXEDIR%;%PATH%

REM :: Make Script-Dir to current dir
%HOMEDRIVE%
chdir %EXEDIR%

REM :: Check admin-rights
openfiles >nul 2>&1 || goto norights

REM :: Datum filtern
FOR /F " usebackq tokens=1,2* delims= " %%a IN (`date /t`) DO (
    SET T1=%%a
    SET "T1=!T1:.=!"
)

REM :: Uhrzeit filtern
FOR /F " usebackq tokens=1,2* delims= " %%b IN (`time /t`) DO (
    SET T2=%%b
    SET "T2=!T2::=!"
)

echo Timestamp: %T1%%T2%

if not exist "%EXEDIR%\%TARGET%" (
   set FERR="%EXEDIR%\%TARGET%"
   goto notfound
   )
if not exist "%EXEDIR%\%TARGETICON%" (
   set FERR="%EXEDIR%\%TARGETICON%"
   goto notfound
   )
if not exist "%EXEDIR%\%TARGETVERSION%" (
   set FERR="%EXEDIR%\%TARGETVERSION%"
   goto notfound
   )
if not exist "%EXEDIR%\%TARGETMANIFESTA%" (
   set FERR="%EXEDIR%\%TARGETMANIFESTA%"
   goto notfound
   )
if not exist "%EXEDIR%\%TARGETMANIFESTI%" (
   set FERR="%EXEDIR%\%TARGETMANIFESTI%"
   goto notfound
   )
if not exist "%EXEDIR%\%RESHACKER%" (
   set FERR="%EXEDIR%\%RESHACKER%"
   goto notfound
   )
   
REM :: Make backup of target
echo.
echo.Creating backup of:
echo."%TARGET%" to ...
echo."%TARGET%.backup-%T1%%T2%"
copy /y "%EXEDIR%\%TARGET%" "%EXEDIR%\%TARGET%.backup-%T1%%T2%" >nul 2>&1
echo.

REM :: ADDITION WITH NUMBER
"%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:14 -name:99 -lang:1033 -file:"%TARGETICON%" || "%EXEDIR%\%RESHACKER%" -op:add -src:"%EXEDIR%\%TARGET%" -type:14 -name:99 -lang:1033 -file:"%TARGETICON%"
"%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:16 -name:1 -lang:1033 -file:"%TARGETVERSION%" || "%EXEDIR%\%RESHACKER%" -op:add -src:"%EXEDIR%\%TARGET%" -type:16 -name:1 -lang:1033 -file:"%TARGETVERSION%"
REM :: Activate Invoker Requirement
"%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:24 -name:1 -lang:1033 -file:"%TARGETMANIFESTI%" || "%EXEDIR%\%RESHACKER%" -op:add -src:"%EXEDIR%\%TARGET%" -type:24 -name:1 -lang:1033 -file:"%TARGETMANIFESTI%"
REM :: Activate Admin Requirement
REM :: "%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:24 -name:1 -lang:1033 -file:"%TARGETMANIFESTA%" || "%EXEDIR%\%RESHACKER%" -op:add -src:"%EXEDIR%\%TARGET%" -type:24 -name:1 -lang:1033 -file:"%TARGETMANIFESTA%"

REM :: ADDITION WITH NAME
REM :: "%EXEDIR%\%RESHACKER%" -op:add -src:"%EXEDIR%\%TARGET%" -type:icon -name:99 -lang:2057 -file:"%TARGETICON%"
REM :: "%EXEDIR%\%RESHACKER%" -op:add -src:"%EXEDIR%\%TARGET%" -type:Version -name:1 -lang:1031 -file:"%TARGETVERSION%"

REM :: UPDATE WITH NUMBER
REM :: "%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:14 -name:99 -lang:2057 -file:"%TARGETICON%"
REM :: "%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:16 -name:1 -lang:1031 -file:"%TARGETVERSION%"
REM :: UPDATE WITH NAME
REM :: "%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:icon -name:99 -lang:2057 -file:"%TARGETICON%"
REM :: "%EXEDIR%\%RESHACKER%" -op:upd -src:"%EXEDIR%\%TARGET%" -type:Version -name:1 -lang:1031 -file:"%TARGETVERSION%"
goto end

:notfound
color 4E
echo.
echo ERROR:
echo.
echo %FERR%
echo.
echo ... not found.
echo Please check it out ...
echo.
goto end

:norights
color 4E
echo.
echo ERROR:
echo.
echo You have no admin-rights ...
echo.
goto end

:end
echo Finished.
ENDLOCAL
echo Hit ENTER to Exit ...
pause >nul
color
