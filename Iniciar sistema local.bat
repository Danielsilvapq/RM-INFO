@echo off
rem Windows: clique duas vezes para abrir o sistema neste computador.
cd /d "%~dp0servidor"
start "" http://localhost:3300
node --no-warnings server.js
pause
