@echo off
title IVY Animal Shelter - Launcher
cd /d "%~dp0"

REM Try python first, then py (Windows launcher)
python app.py
if errorlevel 1 py app.py

pause