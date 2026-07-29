@echo off
echo Opening Windows Firewall port 8000 for R3P Backend...
netsh advfirewall firewall add rule name="R3P Backend Port 8000" dir=in action=allow protocol=TCP localport=8000
echo.
echo Firewall rule added successfully!
pause
