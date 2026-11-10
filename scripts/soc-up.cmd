@echo off
rem Duplo clique: liga o SOC neste PC e aponta o agente da VPS para ca.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0soc-up.ps1"
pause
