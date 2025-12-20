<<<<<<< HEAD
@echo off
title IVY Animal Shelter - Launcher
cd /d "%~dp0"
python app.py
if errorlevel 1 py app.py
pause
=======
@echo off
title IVY Animal Shelter - Launcher
cd /d "%~dp0"

REM Try python first, then py (Windows launcher)
python app.py
if errorlevel 1 py app.py

pause
>>>>>>> 10bab7d85d76e9b1071747dc093b4733c6355911
