 Deploying the AI Lab App on an AWS Ubuntu Server

This guide walks through deploying the app on a fresh Ubuntu server in AWS, including Python setup, Ollama, the `mistral` model, and the `systemd` service.

## 1. Launch the Ubuntu Server

Use Ubuntu 22.04 or 24.04 LTS.

Make sure the AWS security group allows:
- `22/tcp` from your IP for SSH
- `8000/tcp` from the users who should access the web app

If you want GPU acceleration for Ollama, use an NVIDIA-backed instance type.

SSH into the server:

```bash
ssh -i <your-key>.pem ubuntu@<server-public-ip>
```

## 2. Install Base Packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip curl unzip
```

If this is a GPU instance, verify the NVIDIA drivers are working:

```bash
nvidia-smi
```

## 3. Create the App Directory

```bash
mkdir -p /home/ubuntu/lama/docs
cd /home/ubuntu/lama
```

## 4. Copy the App Files

Copy at least these files to the server:
- `app.py`
- `docs/policy.txt`
- `docs/internal_notes.txt`

From your local machine:

```bash
scp -i <your-key>.pem app.py ubuntu@<server-public-ip>:/home/ubuntu/lama/app.py
scp -i <your-key>.pem docs/policy.txt ubuntu@<server-public-ip>:/home/ubuntu/lama/docs/policy.txt
scp -i <your-key>.pem docs/internal_notes.txt ubuntu@<server-public-ip>:/home/ubuntu/lama/docs/internal_notes.txt
```

## 5. Create the Python Virtual Environment

```bash
cd /home/ubuntu/lama
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" httpx pydantic
deactivate
```

## 6. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start and enable the Ollama service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl restart ollama
sudo systemctl status ollama
```

## 7. Pull the Mistral Model

```bash
ollama pull mistral
ollama list
```

Optional verification:

```bash
ollama run mistral "hello"
```

If this is a GPU instance and Ollama appears stuck, test CPU-only:

```bash
CUDA_VISIBLE_DEVICES="" ollama run mistral "hello"
```

## 8. Create the `systemd` Service for the App

Create the file `/etc/systemd/system/lama-ctf.service` with the following contents:

```ini
[Unit]
Description=Lama CTF FastAPI
After=network.target ollama.service
Requires=ollama.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/lama
Environment="PATH=/home/ubuntu/lama/.venv/bin:/usr/bin:/bin"
Environment="CTF_FLAG=flag{your_real_flag_here}"
Environment="OLLAMA_HOST=http://127.0.0.1:11434"
Environment="OLLAMA_MODEL=mistral"
ExecStart=/home/ubuntu/lama/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Then reload `systemd` and start the app:

```bash
sudo systemctl daemon-reload
sudo systemctl enable lama-ctf
sudo systemctl restart lama-ctf
sudo systemctl status lama-ctf
```

## 9. Verify the App

From the server:

```bash
curl http://127.0.0.1:8000/info
```

From your browser:

```text
http://<server-public-ip>:8000
```

You should see the web app load successfully.

## 10. Configure Prisma AIRS

The app supports runtime AIRS configuration from the web UI, so you do not need to preconfigure AIRS in the service file.

If you want to preconfigure AIRS in `systemd`, add these lines to the `Service` section:

```ini
Environment="AIRS_API_TOKEN=<your_token>"
Environment="AIRS_PROFILE_NAME=<your_profile>"
```

Then restart the app:

```bash
sudo systemctl daemon-reload
sudo systemctl restart lama-ctf
```

## 11. Useful Operations

View app logs:

```bash
sudo journalctl -u lama-ctf -f
```

View Ollama logs:

```bash
sudo journalctl -u ollama -f
```

Restart both services:

```bash
sudo systemctl restart ollama
sudo systemctl restart lama-ctf
```

## 12. Notes for AWS AMI Reuse

If you later create an AMI from this server and launch a new GPU instance from it, Ollama may still need to be reinstalled or repaired on first boot. For fresh manual deployments, the steps above are enough.
