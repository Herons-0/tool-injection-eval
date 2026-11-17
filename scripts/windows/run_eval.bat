@echo off
rem Double-click to run tool-injection-eval against Gemini on Windows.
rem Results, logs and STATUS.txt are written into this folder.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_eval.ps1"
echo.
echo Finished. Results (if any) are in results\RESULTS.md next to this file.
pause
