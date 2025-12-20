@echo off
title IVY Animal Shelter - Launcher
cd /d "%~dp0"
python app.py
if errorlevel 1 py app.py
pause
