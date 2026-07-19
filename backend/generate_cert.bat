@echo off
echo Generating self-signed certificate for R3P Server...
mkdir certs 2>nul
openssl req -x509 -newkey rsa:4096 -keyout certs\key.pem -out certs\cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
echo.
echo Certificate generated in backend\certs!
echo Run the server using: uvicorn main:app --ssl-keyfile=certs\key.pem --ssl-certfile=certs\cert.pem
