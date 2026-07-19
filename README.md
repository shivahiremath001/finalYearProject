# R3P - Ransomware Readiness & Risk Profiler

R3P is a security telemetry tool designed to evaluate a Windows machine's exposure to ransomware attacks. The project maps security configurations to a realistic Ransomware Kill Chain to calculate a risk score and dynamically classify the machine.

## Architecture

R3P consists of two main components:
1. **Agent (`collector.py`)**: A standalone, lightweight Windows executable that scans the system for security misconfigurations (Entry Vector, Execution, Evasion, Lateral Movement, Recovery Prevention). It presents a Tkinter GUI and posts telemetry to the backend.
2. **Backend (`backend/main.py`)**: A FastAPI server that ingests agent telemetry, computes a severity-weighted risk score, persists the data to a SQLite database (`r3p.db`), and exposes endpoints to retrieve machine data.

```
[ Windows Machine (R3P Agent) ]
            |
            | (POST /ingest with X-API-Key)
            v
[ FastAPI Backend (Scoring Engine) ]
            |
            | (SQLAlchemy)
            v
[ SQLite Database (r3p.db) ]
```

## Security Notes

### API Key Authentication
R3P uses a shared-secret model (`X-API-Key` header) to protect its endpoints. This prevents an unauthenticated, compromised host from reporting false "all clear" telemetry.
*Note: This simple shared-secret approach is appropriate for small, trusted deployments or lab environments. For a production deployment, the next step would be implementing per-machine tokens or mTLS.*

### HTTPS / Self-Signed Certificates
For secure transport over the network, R3P supports HTTPS. For demonstration and lab purposes, a script (`generate_cert.py` / `generate_cert.bat`) is included to easily create self-signed certificates using OpenSSL.
*Note: This uses a self-signed cert for demonstration purposes only. A real deployment would use a certificate from an internal CA or Let's Encrypt, and agent requests should never disable certificate verification (`verify=False`) outside of a lab environment.*

## Future Work
- **Schema Normalization**: Refactoring the fixed boolean columns for each configuration check into a normalized `CheckResult` table for better extensibility.
- **Queued Ingestion**: Using a message broker (e.g., RabbitMQ/Kafka) for fleet-scale deployments.
- **Advanced Auth**: Per-machine tokens or mTLS instead of a shared API key.
