import os
import subprocess


def main():
    print("Generating self-signed certificate for R3P Server...")

    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)

    # OpenSSL command to generate a self-signed certificate
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:4096",
        "-keyout",
        "certs/key.pem",
        "-out",
        "certs/cert.pem",
        "-sha256",
        "-days",
        "365",
        "-nodes",
        "-subj",
        "/CN=localhost",
    ]

    try:
        subprocess.run(cmd, check=True)
        print("\nCertificate generated successfully in backend/certs!")
        print("Run the server using:")
        print(
            "  uvicorn main:app --ssl-keyfile=certs/key.pem --ssl-certfile=certs/cert.pem"
        )
    except FileNotFoundError:
        print("\nError: openssl is not installed or not in your system PATH.")
        print("Please install OpenSSL or use the CLI directly if available.")
    except subprocess.CalledProcessError as e:
        print(f"\nError running openssl command: {e}")


if __name__ == "__main__":
    main()
