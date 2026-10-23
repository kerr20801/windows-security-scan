@echo off
title Windows Security Scan
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0security-scan-v4.ps1"
pause
