# SpectrePot — Public Deployment & Production Guide

This guide covers step-by-step instructions to deploy SpectrePot to the public internet in two distinct operational environments:
1. **Scenario A: Cloud Deployment on Amazon Web Services (AWS EC2)**
2. **Scenario B: Self-Hosted Deployment on Proxmox VE (Home Lab / DMZ)**

---

## Architecture Overview

```
                          PUBLIC INTERNET
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
         [Scenario A: AWS]               [Scenario B: Proxmox VE]
                 │                               │
       AWS VPC Security Group            Home Router (VLAN / DMZ)
       (Firewall Isolation)              (LAN-Drop Isolation Rules)
                 │                               │
          EC2 Instance                      Proxmox VM/LXC
    (Moving Real SSH to 55222)           (Isolated Bridge vmbr1)
                 │                               │
        iptables NAT Rules              iptables NAT Rules
    (22->2222, 80->8080, 23->2323)    (22->2222, 80->8080, 23->2323)
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                         ATTACKME ENGINE
```

---

# Scenario 1: Cloud Deployment on AWS (Amazon Web Services)

Deploying on AWS EC2 gives you a dedicated public IPv4 address completely isolated from your personal devices.

### Step 1.1: Launch an AWS EC2 Instance
1. Log in to the **AWS Management Console** and navigate to **EC2**.
2. Click **Launch Instance**:
   - **Name**: `spectrepot-honeypot`
   - **AMI**: `Ubuntu Server 24.04 LTS` or `22.04 LTS` (64-bit x86 or ARM).
   - **Instance Type**: `t3.micro` or `t4g.nano` (Free Tier eligible or ~$3–$5/month).
   - **Key Pair**: Create or select an existing `.pem` / `.ed25519` key pair.
   - **Storage**: Default 8 GB – 20 GB gp3 SSD.

### Step 1.2: Configure AWS Security Group (Firewall)
Configure the **Inbound Rules** for your Security Group:

| Type | Port Range | Source | Purpose |
| :--- | :--- | :--- | :--- |
| **Custom TCP** | `55222` | **`My IP`** | Real Admin SSH (Keep private to your IP) |
| **Custom TCP** | `8000` | **`My IP`** | Web Dashboard (Keep private to your IP) |
| **SSH** | `22` | `0.0.0.0/0` (Anywhere) | Decoy SSH (Redirected to 2222) |
| **HTTP** | `80` | `0.0.0.0/0` (Anywhere) | Decoy Web Trap (Redirected to 8080) |
| **Custom TCP** | `23` | `0.0.0.0/0` (Anywhere) | Decoy Telnet (Redirected to 2323) |
| **Custom TCP** | `2121, 3306, 3389, 5900, 6379` | `0.0.0.0/0` (Anywhere) | Decoy Recon Traps (FTP, MySQL, RDP, VNC, Redis) |

> **IMPORTANT**: Allocate and attach an **Elastic IP** to your EC2 instance so its public IP address never changes when restarted.

---

### Step 1.3: Secure the Real Host SSH
Connect to your EC2 instance using the default key:
```bash
ssh -i your-key.pem ubuntu@YOUR_AWS_PUBLIC_IP
```

Before redirecting port 22 to the honeypot, move the real SSH daemon to port `55222`:

1. Edit SSH server configuration:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
2. Change or add:
   ```ini
   Port 55222
   PermitRootLogin no
   PasswordAuthentication no
   ```
3. Restart SSH daemon:
   ```bash
   sudo systemctl restart ssh || sudo systemctl restart sshd
   ```
4. **Open a new terminal window** and verify you can connect on port 55222 before closing your current session:
   ```bash
   ssh -i your-key.pem -p 55222 ubuntu@YOUR_AWS_PUBLIC_IP
   ```

---

### Step 1.4: Clone & Install SpectrePot on EC2

```bash
# Update packages and install python
sudo apt update && sudo apt install -y python3 python3-pip git iptables-persistent

# Clone your project repo or upload project files
git clone <YOUR_REPO_URL> ~/spectrepot
cd ~/spectrepot

# Install Python dependencies
pip3 install -r requirements.txt --break-system-packages
```

---

### Step 1.5: Configure iptables Port Forwarding
Standard internet scanners target low privileged ports (22, 80, 23). Redirect them to SpectrePot's unprivileged ports (2222, 8080, 2323):

```bash
# SSH Port 22 -> 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# HTTP Port 80 -> 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Telnet Port 23 -> 2323
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323

# Save iptables rules across reboots
sudo netfilter-persistent save
```

---

### Step 1.6: Configure Station Node Coordinates
Edit `backend/config.py` on the server and update your station's actual AWS region/coordinates:
```python
HONEYPOT_NODE = {
    "name": "AWS-EC2-Production-Node",
    "ip": "YOUR_AWS_ELASTIC_IP",
    "lat": 38.9072,        # e.g., us-east-1 (Virginia)
    "lon": -77.0369,
    "city": "Ashburn",
    "country": "United States",
    "country_code": "US"
}
```

---

### Step 1.7: Run as a 24/7 Systemd Service
Create a background service so SpectrePot starts automatically on boot:

```bash
sudo nano /etc/systemd/system/spectrepot.service
```

Paste:
```ini
[Unit]
Description=SpectrePot Honeypot Platform
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/spectrepot
ExecStart=/usr/bin/python3 run.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now spectrepot
```

Access your web dashboard at **`http://YOUR_AWS_PUBLIC_IP:8000`**.

---

# Scenario 2: Self-Hosting on Proxmox VE (Home Lab)

When hosting on hardware in your home, **network segmentation is critical** to prevent any attacker from pivoting from the honeypot into your private home devices (NAS, laptops, IoT).

---

### Step 2.1: Create an Isolated VM or LXC Container in Proxmox
1. Open the Proxmox Web GUI (`https://proxmox-ip:8006`).
2. Create a new **LXC Container** or **KVM Virtual Machine**:
   - **OS**: Ubuntu 24.04 or Debian 12 Minimal.
   - **Cores**: 1–2 vCPUs.
   - **RAM**: 1 GB – 2 GB.
   - **Disk**: 10 GB – 20 GB.

### Step 2.2: Network Isolation (DMZ / VLAN Setup)
In Proxmox, assign the honeypot container/VM to an isolated bridge or VLAN tag:
- **Network Interface**: Bridge `vmbr0`, VLAN Tag `50` (e.g. `192.168.50.10/24`).

**On your Home Router / Firewall (pfSense / OPNsense / UniFi / OpenWrt):**
1. Create firewall rules for VLAN 50:
   - **Allow**: Honeypot Subnet -> Internet (WAN).
   - **BLOCK / DROP**: Honeypot Subnet -> Private LAN subnets (`192.168.1.0/24`, `10.0.0.0/8`, `172.16.0.0/12`).
   - **BLOCK**: Honeypot Subnet -> Router Management Web Interface (`192.168.1.1` port 80/443).

This ensures that even if an attacker were to escape a service sandbox, they are trapped in a dead-end network.

---

### Step 2.3: Port Redirection & Service Setup on the Proxmox VM

Inside the Proxmox Container / VM console:

1. **Move Host Management SSH:**
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Set: Port 55222
   sudo systemctl restart ssh
   ```
2. **Install SpectrePot:**
   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip git iptables-persistent
   git clone <YOUR_REPO_URL> /opt/spectrepot
   cd /opt/spectrepot
   pip3 install -r requirements.txt --break-system-packages
   ```
3. **Set up iptables NAT:**
   ```bash
   sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
   sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
   sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
   sudo netfilter-persistent save
   ```
4. **Create Systemd Service:**
   ```bash
   sudo nano /etc/systemd/system/spectrepot.service
   ```
   Paste:
   ```ini
   [Unit]
   Description=SpectrePot Honeypot Platform
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/spectrepot
   ExecStart=/usr/bin/python3 run.py
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
   Enable:
   ```bash
   sudo systemctl enable --now spectrepot
   ```

---

### Step 2.4: Exposing Ports to the Internet

Choose one of two options depending on your ISP setup:

#### Option A: Port Forwarding on Your Home Router (Static/Dynamic Public IP)
Log in to your home router and create Port Forwarding rules pointing from your WAN to your Proxmox VM's IP (`192.168.50.10`):

| External Port | Internal IP | Internal Port | Protocol |
| :--- | :--- | :--- | :--- |
| `22` | `192.168.50.10` | `22` (redirected to 2222 by VM) | TCP |
| `80` | `192.168.50.10` | `80` (redirected to 8080 by VM) | TCP |
| `23` | `192.168.50.10` | `23` (redirected to 2323 by VM) | TCP |
| `2121, 3306, 3389, 5900, 6379` | `192.168.50.10` | Same | TCP |

> **Note**: **Do NOT forward port `8000`** on your home router! Keep the dashboard accessible only from your local home network at `http://192.168.50.10:8000`.

#### Option B: If Behind CGNAT (Carrier-Grade NAT)
If your ISP does not provide a public IPv4 address (CGNAT), use a **Cloudflare Tunnel** or a **WireGuard Reverse Proxy on a $3/mo VPS** to forward incoming TCP traffic to your Proxmox honeypot.

---

## 🔒 Security Best Practices Checklist

- [ ] **Real SSH Moved**: Management SSH is on port `55222` with password auth disabled.
- [ ] **Dashboard Secured**: Port `8000` is never exposed to the public internet (restricted to `My IP` on AWS, or internal LAN only on Proxmox).
- [ ] **Isolated Outbound Traffic**: Prevent the honeypot from making outbound spam/DDoS connections by restricting outbound ports to DNS (53), HTTP/HTTPS (80/443), and GeoIP lookup.
- [ ] **Backups Enabled**: Set Proxmox snapshot / AWS AMI backup schedules.

