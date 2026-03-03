#!/bin/bash
set -euxo pipefail

# ---------------------------------------------------------------------------
# 1. Write IoT certificates
# ---------------------------------------------------------------------------
mkdir -p /etc/aws-iot
chmod 755 /etc/aws-iot

cat <<'FILE' > /etc/aws-iot/device-cert.pem
${DEVICE_CERT}
FILE

cat <<'FILE' > /etc/aws-iot/private-key.pem
${PRIVATE_KEY}
FILE

chmod 644 /etc/aws-iot/device-cert.pem
chmod 600 /etc/aws-iot/private-key.pem

# Download Amazon Root CA
curl -fsSL -o /etc/aws-iot/AmazonRootCA1.pem \
  https://www.amazontrust.com/repository/AmazonRootCA1.pem

# ---------------------------------------------------------------------------
# 2. System packages
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-pip python3-dev python3-venv awscli jq

# ---------------------------------------------------------------------------
# 3. Python dependencies
#    - awsiotsdk  : AWS IoT Device SDK v2 (provides awscrt + awsiot)
#    - python-dotenv : used by mqtt_publish.py to load /home/ubuntu/.env
# ---------------------------------------------------------------------------
pip3 install --break-system-packages awsiotsdk python-dotenv

# ---------------------------------------------------------------------------
# 4. Write .env for mqtt_publish.py
#    All variables that mqtt_publish.py reads via os.getenv()
# ---------------------------------------------------------------------------
cat <<EOF > /home/ubuntu/.env
ENDPOINT=${ENDPOINT}
CLIENT_ID=python-publisher
TOPIC=topic/mqtt
PUBLISH_INTERVAL=5
PATH_TO_CERT=/etc/aws-iot/device-cert.pem
PATH_TO_KEY=/etc/aws-iot/private-key.pem
PATH_TO_ROOT=/etc/aws-iot/AmazonRootCA1.pem
EOF

chown ubuntu:ubuntu /home/ubuntu/.env
chmod 600 /home/ubuntu/.env

# ---------------------------------------------------------------------------
# 5. Deploy mqtt_publish.py
# ---------------------------------------------------------------------------
mkdir -p /opt/iot-publisher
cat <<'PYEOF' > /opt/iot-publisher/mqtt_publish.py
${MQTT_SCRIPT}
PYEOF

chown -R ubuntu:ubuntu /opt/iot-publisher
chmod +x /opt/iot-publisher/mqtt_publish.py

# ---------------------------------------------------------------------------
# 6. Create systemd service so the publisher starts on boot
#    and restarts automatically on failure
# ---------------------------------------------------------------------------
cat <<'SERVICE' > /etc/systemd/system/mqtt-publisher.service
[Unit]
Description=AWS IoT MQTT Publisher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/iot-publisher
EnvironmentFile=/home/ubuntu/.env
ExecStart=/usr/bin/python3 /opt/iot-publisher/mqtt_publish.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable mqtt-publisher.service
systemctl start mqtt-publisher.service