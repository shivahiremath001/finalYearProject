# How to Run the R3P System on a Local Wi-Fi Network

This guide explains step-by-step how to run the R3P Server and Dashboard on one main computer (Host) and connect multiple agent machines or access the dashboard from any device (phone, laptop, desktop) connected to the **same Wi-Fi network**.

---

## Method 1: Automatic 1-Click Start (Recommended)

1. Connect your **Host Computer** (the machine running the backend/database) and all **Agent Devices** to the **same Wi-Fi network**.
2. Right-click [`run_local_wifi.bat`](file:///c:/Users/SHIVA/OneDrive/FINAL_PROJECT_serverside/run_local_wifi.bat) in the project root folder and select **Run as Administrator**.
3. Two terminal windows will pop up automatically:
   - **R3P Backend Server (LAN):** Listens on port `8000`.
   - **R3P Frontend Server (LAN):** Listens on port `5173`.
4. Look at the main batch terminal window. It will display your Host IPv4 Address (e.g., `192.168.1.15`).

---

## Method 2: Manual Step-by-Step Setup

If you prefer to run the steps manually or troubleshoot network issues, follow these steps:

### Step 1: Find Host Computer's IPv4 Address
On the main **Host PC**:
1. Open Command Prompt (`cmd`).
2. Type `ipconfig` and press **Enter**.
3. Locate your active Wi-Fi adapter and note down the **IPv4 Address** (e.g., `192.168.1.15`).

### Step 2: Open Windows Firewall Port 8000
By default, Windows Firewall blocks incoming network connections to Python services. To unblock:
1. Open **Command Prompt as Administrator**.
2. Run:
   ```cmd
   netsh advfirewall firewall add rule name="R3P Backend Port 8000" dir=in action=allow protocol=TCP localport=8000
   ```

### Step 3: Start the Backend Server
Open a terminal in the project folder and execute:
```cmd
cd backend
venv\Scripts\activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
> **Note:** Binding to `--host 0.0.0.0` is essential. It tells the backend to listen for incoming connections from *all* local network interfaces, not just `localhost`.

### Step 4: Start the Frontend Dashboard
Open a second terminal window and execute:
```cmd
cd frontend
npm run dev -- --host
```
> **Note:** Adding `-- --host` tells Vite to expose the Web UI across your local Wi-Fi network.

---

## How to Connect Other Devices on the Same Wi-Fi

### 1. View Dashboard from Mobile or Secondary Laptops
Open any web browser on any device connected to the Wi-Fi network and navigate to:
```text
http://<HOST_IP>:5173
```
*(Example: `http://192.168.1.15:5173`)*

### 2. Connect Remote Collector Agents
To run agent node monitoring on other computers connected to the same Wi-Fi:

#### Option A: Via Command Line
Run the collector script specifying the host IP:
```cmd
python collector.py --server http://<HOST_IP>:8000
```
*(Example: `python collector.py --server http://192.168.1.15:8000`)*

#### Option B: Via `r3p_server.txt` Config
1. Create or edit `r3p_server.txt` in the same directory as `collector.py` or `collector.exe`.
2. Write the host URL inside:
   ```text
   http://192.168.1.15:8000
   ```
3. Launch `collector.py` or double-click `collector.exe`. It will automatically connect to the Host server.

---

## Troubleshooting & FAQs

- **Devices cannot connect / Timeout Error:**
  Make sure your Wi-Fi network profile on Windows is set to **Private Network** (Settings > Network & Internet > Wi-Fi > Network Profile Type). Windows Firewall blocks ports by default on "Public" network profiles.
- **Can't run batch file firewall rule?**
  Ensure you right-clicked `run_local_wifi.bat` and selected **Run as Administrator**.
